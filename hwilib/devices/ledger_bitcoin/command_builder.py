import enum
from typing import List, Tuple, Mapping, Union, Iterator, Optional

from hashlib import sha256

from ..._serialize import ser_compact_size as write_varint
from .merkle import get_merkleized_map_commitment, MerkleTree, element_hash
from ...wallet_policy import WalletPolicy

# p2 encodes the protocol version implemented
CURRENT_PROTOCOL_VERSION = 1

# version number in Ledger's serialization of wallet policies
CURRENT_WALLET_POLICY_VERSION = 2


def bip32_path_from_string(path: str) -> List[bytes]:
    splitted_path: List[str] = path.split("/")

    if not splitted_path:
        raise Exception(f"BIP32 path format error: '{path}'")

    if "m" in splitted_path and splitted_path[0] == "m":
        splitted_path = splitted_path[1:]

    return [int(p).to_bytes(4, byteorder="big") if "'" not in p
            else (0x80000000 | int(p[:-1])).to_bytes(4, byteorder="big")
            for p in splitted_path]


def chunkify(data: bytes, chunk_len: int) -> Iterator[Tuple[bool, bytes]]:
    size: int = len(data)

    if size <= chunk_len:
        yield True, data
        return

    chunk: int = size // chunk_len
    remaining: int = size % chunk_len
    offset: int = 0

    for i in range(chunk):
        yield False, data[offset: offset + chunk_len]
        offset += chunk_len

    if remaining:
        yield True, data[offset:]


def serialize_str(value: str) -> bytes:
    return len(value).to_bytes(1, byteorder="big") + value.encode("latin-1")

def serialize_wallet_policy(wallet_policy: WalletPolicy) -> bytes:
    keys_info_hashes = map(lambda k: element_hash(k.encode()), wallet_policy.keys_info)
    return b"".join([
        CURRENT_WALLET_POLICY_VERSION.to_bytes(1, byteorder="big"),
        serialize_str(wallet_policy.name),
        write_varint(len(wallet_policy.descriptor_template.encode())),
        sha256(wallet_policy.descriptor_template.encode()).digest(),
        write_varint(len(wallet_policy.keys_info)),
        MerkleTree(keys_info_hashes).root
    ])

def get_wallet_policy_id(wallet_policy: WalletPolicy) -> bytes:
    return sha256(serialize_wallet_policy(wallet_policy)).digest()

class DefaultInsType(enum.IntEnum):
    GET_VERSION = 0x01

class BitcoinInsType(enum.IntEnum):
    GET_EXTENDED_PUBKEY = 0x00
    GET_ADDRESS = 0x01
    REGISTER_WALLET = 0x02
    GET_WALLET_ADDRESS = 0x03
    SIGN_PSBT = 0x04
    GET_MASTER_FINGERPRINT = 0x05
    SIGN_MESSAGE = 0x10

class FrameworkInsType(enum.IntEnum):
    CONTINUE_INTERRUPTED = 0x01


class BitcoinCommandBuilder:
    """APDU command builder for the Bitcoin application."""

    CLA_DEFAULT: int = 0xB0
    CLA_BITCOIN: int = 0xE1
    CLA_FRAMEWORK: int = 0xF8

    def serialize(
        self,
        cla: int,
        ins: Union[int, enum.IntEnum],
        p1: int = 0,
        p2: int = CURRENT_PROTOCOL_VERSION,
        cdata: bytes = b"",
    ) -> dict:
        """Serialize the whole APDU command (header + data).

        Parameters
        ----------
        cla : int
            Instruction class: CLA (1 byte)
        ins : Union[int, IntEnum]
            Instruction code: INS (1 byte)
        p1 : int
            Instruction parameter 1: P1 (1 byte).
        p2 : int
            Instruction parameter 2: P2 (1 byte).
        cdata : bytes
            Bytes of command data.

        Returns
        -------
        dict
            Dictionary representing the APDU message.

        """

        return {"cla": cla, "ins": ins, "p1": p1, "p2": p2, "data": cdata}

    def get_extended_pubkey(self, bip32_path: List[int], display: bool = False):
        bip32_paths: List[bytes] = bip32_path_from_string(bip32_path)

        cdata: bytes = b"".join([
            b'\1' if display else b'\0',
            len(bip32_paths).to_bytes(1, byteorder="big"),
            *bip32_paths
        ])

        return self.serialize(
            cla=self.CLA_BITCOIN,
            ins=BitcoinInsType.GET_EXTENDED_PUBKEY,
            cdata=cdata,
        )

    def register_wallet(self, wallet: WalletPolicy):
        wallet_bytes = serialize_wallet_policy(wallet)

        return self.serialize(
            cla=self.CLA_BITCOIN,
            ins=BitcoinInsType.REGISTER_WALLET,
            cdata=write_varint(len(wallet_bytes)) + wallet_bytes,
        )

    def get_wallet_address(
        self,
        wallet: WalletPolicy,
        wallet_hmac: Optional[bytes],
        address_index: int,
        change: bool,
        display: bool,
    ):
        cdata: bytes = b"".join(
            [
                b'\1' if display else b'\0',                            # 1 byte
                get_wallet_policy_id(wallet),                           # 32 bytes
                wallet_hmac if wallet_hmac is not None else b'\0' * 32, # 32 bytes
                b"\1" if change else b"\0",                             # 1 byte
                address_index.to_bytes(4, byteorder="big"),             # 4 bytes
            ]
        )

        return self.serialize(
            cla=self.CLA_BITCOIN,
            ins=BitcoinInsType.GET_WALLET_ADDRESS,
            cdata=cdata,
        )

    def sign_psbt(
        self,
        global_mapping: Mapping[bytes, bytes],
        input_mappings: List[Mapping[bytes, bytes]],
        output_mappings: List[Mapping[bytes, bytes]],
        wallet: WalletPolicy,
        wallet_hmac: Optional[bytes],
    ):

        cdata = bytearray()
        cdata += get_merkleized_map_commitment(global_mapping)

        cdata += write_varint(len(input_mappings))
        cdata += MerkleTree(
            [
                element_hash(get_merkleized_map_commitment(m_in))
                for m_in in input_mappings
            ]
        ).root

        cdata += write_varint(len(output_mappings))
        cdata += MerkleTree(
            [
                element_hash(get_merkleized_map_commitment(m_out))
                for m_out in output_mappings
            ]
        ).root

        cdata += get_wallet_policy_id(wallet)
        cdata += wallet_hmac if wallet_hmac is not None else b'\0' * 32

        return self.serialize(
            cla=self.CLA_BITCOIN, ins=BitcoinInsType.SIGN_PSBT, cdata=bytes(cdata)
        )

    def get_master_fingerprint(self):
        return self.serialize(
            cla=self.CLA_BITCOIN,
            ins=BitcoinInsType.GET_MASTER_FINGERPRINT
        )

    def sign_message(self, message: bytes, bip32_path: str):
        cdata = bytearray()

        bip32_path: List[bytes] = bip32_path_from_string(bip32_path)

        # split message in 64-byte chunks (last chunk can be smaller)
        n_chunks = (len(message) + 63) // 64
        chunks = [message[64 * i: 64 * i + 64] for i in range(n_chunks)]

        cdata += len(bip32_path).to_bytes(1, byteorder="big")
        cdata += b''.join(bip32_path)

        cdata += write_varint(len(message))

        cdata += MerkleTree(element_hash(c) for c in chunks).root

        return self.serialize(
            cla=self.CLA_BITCOIN,
            ins=BitcoinInsType.SIGN_MESSAGE,
            cdata=bytes(cdata)
        )

    def continue_interrupted(self, cdata: bytes):
        """Command builder for CONTINUE.

        Returns
        -------
        bytes
            APDU command for CONTINUE.

        """
        return self.serialize(
            cla=self.CLA_FRAMEWORK,
            ins=FrameworkInsType.CONTINUE_INTERRUPTED,
            cdata=cdata,
        )
