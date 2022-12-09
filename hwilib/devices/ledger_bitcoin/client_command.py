from enum import IntEnum
from typing import List, Mapping
from collections import deque
from hashlib import sha256
from io import BytesIO

from ...common import sha256
from .merkle import MerkleTree, element_hash
from ..._serialize import ser_compact_size as write_varint


class ByteStreamParser:
    def __init__(self, input: bytes):
        self.stream = BytesIO(input)

    def assert_empty(self) -> bytes:
        if self.stream.read(1) != b'':
            raise ValueError("Byte stream was expected to be empty")

    def read_bytes(self, n: int) -> bytes:
        result = self.stream.read(n)
        if len(result) < n:
            raise ValueError("Byte stream exhausted")
        return result

    def read_uint(self, n: int, byteorder: str = "big") -> int:
        return int.from_bytes(self.read_bytes(n), byteorder)

    def read_varint(self) -> int:
        prefix = self.read_uint(1)

        if prefix == 253:
            return self.read_uint(2, 'little')
        elif prefix == 254:
            return self.read_uint(4, 'little')
        elif prefix == 255:
            return self.read_uint(8, 'little')
        else:
            return prefix


class ClientCommandCode(IntEnum):
    YIELD = 0x10
    GET_PREIMAGE = 0x40
    GET_MERKLE_LEAF_PROOF = 0x41
    GET_MERKLE_LEAF_INDEX = 0x42
    GET_MORE_ELEMENTS = 0xA0


class ClientCommand:
    def execute(self, request: bytes) -> bytes:
        raise NotImplementedError("Subclasses should implement this method.")

    @property
    def code(self) -> int:
        raise NotImplementedError("Subclasses should implement this method.")


class YieldCommand(ClientCommand):
    def __init__(self, results: List[bytes]):
        self.results = results

    @property
    def code(self) -> int:
        return ClientCommandCode.YIELD

    def execute(self, request: bytes) -> bytes:
        self.results.append(request[1:])  # only skip the first byte (command code)
        return b""


class GetPreimageCommand(ClientCommand):
    def __init__(self, known_preimages: Mapping[bytes, bytes], queue: "deque[bytes]"):
        self.queue = queue
        self.known_preimages = known_preimages

    @property
    def code(self) -> int:
        return ClientCommandCode.GET_PREIMAGE

    def execute(self, request: bytes) -> bytes:
        req = ByteStreamParser(request[1:])

        if req.read_bytes(1) != b'\0':
            raise RuntimeError(f"Unsupported request: the first byte should be 0")

        req_hash = req.read_bytes(32)
        req.assert_empty()

        if req_hash in self.known_preimages:
            known_preimage = self.known_preimages[req_hash]

            preimage_len_out = write_varint(len(known_preimage))

            # We can send at most 255 - len(preimage_len_out) - 1 bytes in a single message;
            # the rest will be stored for GET_MORE_ELEMENTS

            max_payload_size = 255 - len(preimage_len_out) - 1

            payload_size = min(max_payload_size, len(known_preimage))

            if payload_size < len(known_preimage):
                # split into list of length-1 bytes elements
                extra_elements = [
                    known_preimage[i: i + 1]
                    for i in range(payload_size, len(known_preimage))
                ]
                # add to the queue any remaining extra bytes
                self.queue.extend(extra_elements)

            return (
                preimage_len_out
                + payload_size.to_bytes(1, byteorder="big")
                + known_preimage[:payload_size]
            )

        # not found
        raise RuntimeError(f"Requested unknown preimage for: {req_hash.hex()}")


class GetMerkleLeafProofCommand(ClientCommand):
    def __init__(self, known_trees: Mapping[bytes, MerkleTree], queue: "deque[bytes]"):
        self.queue = queue
        self.known_trees = known_trees

    @property
    def code(self) -> int:
        return ClientCommandCode.GET_MERKLE_LEAF_PROOF

    def execute(self, request: bytes) -> bytes:
        req = ByteStreamParser(request[1:])

        root = req.read_bytes(32)
        tree_size = req.read_varint()
        leaf_index = req.read_varint()
        req.assert_empty()

        if not root in self.known_trees:
            raise ValueError(f"Unknown Merkle root: {root.hex()}.")

        mt: MerkleTree = self.known_trees[root]

        if leaf_index >= tree_size or len(mt) != tree_size:
            raise ValueError(f"Invalid index or tree size.")

        if len(self.queue) != 0:
            raise RuntimeError(
                "This command should not execute when the queue is not empty."
            )

        proof = mt.prove_leaf(leaf_index)

        # Compute how many elements we can fit in 255 - 32 - 1 - 1 = 221 bytes
        n_response_elements = min((255 - 32 - 1 - 1) // 32, len(proof))
        n_leftover_elements = len(proof) - n_response_elements

        # Add to the queue any proof elements that do not fit the response
        if (n_leftover_elements > 0):
            self.queue.extend(proof[-n_leftover_elements:])

        return b"".join(
            [
                mt.get(leaf_index),
                len(proof).to_bytes(1, byteorder="big"),
                n_response_elements.to_bytes(1, byteorder="big"),
                *proof[:n_response_elements],
            ]
        )


class GetMerkleLeafIndexCommand(ClientCommand):
    def __init__(self, known_trees: Mapping[bytes, MerkleTree]):
        self.known_trees = known_trees

    @property
    def code(self) -> int:
        return ClientCommandCode.GET_MERKLE_LEAF_INDEX

    def execute(self, request: bytes) -> bytes:
        req = ByteStreamParser(request[1:])

        root = req.read_bytes(32)
        leaf_hash = req.read_bytes(32)
        req.assert_empty()

        if root not in self.known_trees:
            raise ValueError(f"Unknown Merkle root: {root.hex()}.")

        try:
            leaf_index = self.known_trees[root].leaf_index(leaf_hash)
            found = 1
        except ValueError:
            leaf_index = 0
            found = 0

        return found.to_bytes(1, byteorder="big") + write_varint(leaf_index)


class GetMoreElementsCommand(ClientCommand):
    def __init__(self, queue: "deque[bytes]"):
        self.queue = queue

    @property
    def code(self) -> int:
        return ClientCommandCode.GET_MORE_ELEMENTS

    def execute(self, request: bytes) -> bytes:
        if len(request) != 1:
            raise ValueError("Wrong request length.")

        if len(self.queue) == 0:
            raise ValueError("No elements to get.")

        element_len = len(self.queue[0])
        if any(len(el) != element_len for el in self.queue):
            raise ValueError(
                "The queue contains elements of different byte length, which is not expected."
            )

        # pop from the queue, keeping the total response length at most 255

        response_elements = bytearray()

        n_added_elements = 0
        while len(self.queue) > 0 and len(response_elements) + element_len <= 253:
            response_elements.extend(self.queue.popleft())
            n_added_elements += 1

        return b"".join(
            [
                n_added_elements.to_bytes(1, byteorder="big"),
                element_len.to_bytes(1, byteorder="big"),
                bytes(response_elements),
            ]
        )


class ClientCommandInterpreter:
    """Interpreter for the client-side commands.

    This class keeps has methods to keep track of:
    - known preimages
    - known Merkle trees from lists of elements

    Moreover, it containes the state that is relevant for the interpreted client side commands:
    - a queue of bytes that contains any bytes that could not fit in a response from the
      GET_PREIMAGE client command (when a preimage is too long to fit in a single message) or the
      GET_MERKLE_LEAF_PROOF command (which returns a Merkle proof, which might be too long to fit
      in a single message). The data in the queue is returned in one (or more) successive
      GET_MORE_ELEMENTS commands from the hardware wallet.

    Finally, it keeps track of the yielded values (that is, the values sent from the hardware
    wallet with a YIELD client command).

    Attributes
    ----------
    yielded: list[bytes]
        A list of all the value sent by the Hardware Wallet with a YIELD client command during thw
        processing of an APDU.
    """

    def __init__(self):
        self.known_preimages: Mapping[bytes, bytes] = {}
        self.known_trees: Mapping[bytes, MerkleTree] = {}

        self.yielded: List[bytes] = []

        queue = deque()

        commands = [
            YieldCommand(self.yielded),
            GetPreimageCommand(self.known_preimages, queue),
            GetMerkleLeafIndexCommand(self.known_trees),
            GetMerkleLeafProofCommand(self.known_trees, queue),
            GetMoreElementsCommand(queue),
        ]

        self.commands = {cmd.code: cmd for cmd in commands}

    def execute(self, hw_response: bytes) -> bytes:
        """Interprets the client command requested by the hardware wallet, returning the appropriet
        response and updating the client interpreter's internal state if appropriate.

        Parameters
        ----------
        hw_response : bytes
            The data content of the SW_INTERRUPTED_EXECUTION sent by the hardware wallet.

        Returns
        -------
        bytes
            The result of the execution of the appropriate client side command, containing the response
            to be sent via INS_CONTINUE.
        """

        if len(hw_response) == 0:
            raise RuntimeError(
                "Unexpected empty SW_INTERRUPTED_EXECUTION response from hardware wallet."
            )

        cmd_code = hw_response[0]
        if cmd_code not in self.commands:
            raise RuntimeError(
                "Unexpected command code: 0x{:02X}".format(cmd_code)
            )

        return self.commands[cmd_code].execute(hw_response)

    def add_known_preimage(self, element: bytes) -> None:
        """Adds a preimage to the list of known preimages.

        The client must respond with `element` when a GET_PREIMAGE command is sent with
        `sha256(element)` in its request.

        Parameters
        ----------
        element : bytes
            An array of bytes whose preimage must be known to the client during an APDU execution.
        """

        self.known_preimages[sha256(element)] = element

    def add_known_list(self, elements: List[bytes]) -> None:
        """Adds a known Merkleized list.

        Builds the Merkle tree of `elements`, and adds it to the Merkle trees known to the client
        (mapped by Merkle root `mt_root`).
        moreover, adds all the leafs (after adding the b'\0' prefix) to the list of known preimages.

        If `el` is one of `elements`, the client must respond with b'\0' + `el` when a GET_PREIMAGE
        client command is sent with `sha256(b'\0' + el)`.
        Moreover, the commands GET_MERKLE_LEAF_INDEX and GET_MERKLE_LEAF_PROOF must correctly answer
        queries relative to the Merkle whose root is `mt_root`.

        Parameters
        ----------
        elements : List[bytes]
            A list of `bytes` corresponding to the leafs of the Merkle tree.
        """

        for el in elements:
            self.add_known_preimage(b"\x00" + el)

        mt = MerkleTree(element_hash(el) for el in elements)

        self.known_trees[mt.root] = mt

    def add_known_mapping(self, mapping: Mapping[bytes, bytes]) -> None:
        """Adds the Merkle trees of keys, and the Merkle tree of values (ordered by key)
        of a mapping of bytes to bytes.

        Adds the Merkle tree of the list of keys, and the Merkle tree of the list of corresponding
        values, with the same semantics as the `add_known_list` applied separately to the two lists. 

        Parameters
        ----------
        mapping : Mapping[bytes, bytes]
            A mapping whose keys and values are `bytes`.
        """

        items_sorted = list(sorted(mapping.items()))

        keys = [i[0] for i in items_sorted]
        values = [i[1] for i in items_sorted]
        self.add_known_list(keys)
        self.add_known_list(values)
