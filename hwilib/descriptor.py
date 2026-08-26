"""
Output Script Descriptors
*************************

HWI has a more limited implementation of descriptors.
See `Bitcoin Core's documentation <https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md>`_ for more details on descriptors.

This implementation only supports ``sh()``, ``wsh()``, ``pkh()``, ``wpkh()``, ``multi()``, and ``sortedmulti()`` descriptors.
Descriptors can be parsed, however the actual scripts are not generated.
"""


from .key import (
    ExtendedKey,
    KeyOriginInfo,
    is_hardened,
    parse_multipath,
    multipath_to_string,
    path_to_string,
)
from .common import AddressType
from .errors import BadArgumentError, InvalidPolicyError
from ._serialize import (
    deser_compact_size,
    deser_string,
    ser_compact_size,
    ser_string,
)

from base64 import b64decode, b64encode
from binascii import unhexlify
from copy import deepcopy
from enum import Enum
from io import BufferedReader, BytesIO
from typing import (
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
)


MAX_TAPROOT_NODES = 128


_MINISCRIPT_WRAPPERS = set("acdjlnstuv")
_MINISCRIPT_KEY_FRAGMENTS = {"pk", "pk_k", "pk_h", "pkh"}
_MINISCRIPT_TAPSCRIPT_MULTI_FRAGMENTS = {"multi_a", "sortedmulti_a"}
_MINISCRIPT_TIMELOCK_FRAGMENTS = {"older", "after"}
_MINISCRIPT_HASH_FRAGMENTS = {"sha256": 64, "hash256": 64, "ripemd160": 40, "hash160": 40}
_MINISCRIPT_BINARY_FRAGMENTS = {"and_v", "and_b", "and_n", "or_b", "or_c", "or_d", "or_i"}


def PolyMod(c: int, val: int) -> int:
    """
    :meta private:
    Function to compute modulo over the polynomial used for descriptor checksums
    From: https://github.com/bitcoin/bitcoin/blob/master/src/script/descriptor.cpp
    """
    c0 = c >> 35
    c = ((c & 0x7ffffffff) << 5) ^ val
    if (c0 & 1):
        c ^= 0xf5dee51989
    if (c0 & 2):
        c ^= 0xa9fdca3312
    if (c0 & 4):
        c ^= 0x1bab10e32d
    if (c0 & 8):
        c ^= 0x3706b1677a
    if (c0 & 16):
        c ^= 0x644d626ffd
    return c

def DescriptorChecksum(desc: str) -> str:
    """
    Compute the checksum for a descriptor

    :param desc: The descriptor string to compute a checksum for
    :return: A checksum
    """
    INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
    CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    c = 1
    cls = 0
    clscount = 0
    for ch in desc:
        pos = INPUT_CHARSET.find(ch)
        if pos == -1:
            return ""
        c = PolyMod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        clscount += 1
        if clscount == 3:
            c = PolyMod(c, cls)
            cls = 0
            clscount = 0
    if clscount > 0:
        c = PolyMod(c, cls)
    for j in range(0, 8):
        c = PolyMod(c, 0)
    c ^= 1

    ret = [''] * 8
    for j in range(0, 8):
        ret[j] = CHECKSUM_CHARSET[(c >> (5 * (7 - j))) & 31]
    return ''.join(ret)

def AddChecksum(desc: str) -> str:
    """
    Compute and attach the checksum for a descriptor

    :param desc: The descriptor string to add a checksum to
    :return: Descriptor with checksum
    """
    return desc + "#" + DescriptorChecksum(desc)


def _parse_ranged_deriv_path(path_str: str) -> Tuple[Optional[List[List[int]]], bool]:
    """
    :meta private:

    Parse a derivation path suffix that may end with a ``/*`` range marker.

    :param path_str: The derivation path, without the leading ``/`` that separates it from the key
    :return: The multipath derivation path, or ``None`` if there is none, and whether the path is ranged
    :raises: ValueError: if the derivation path is malformed
    """
    ranged = path_str.endswith("*")
    if ranged:
        if path_str == "*":
            path_str = ""
        elif path_str.endswith("/*"):
            path_str = path_str[:-2]
        else:
            raise ValueError(f"Invalid ranged derivation path: /{path_str}")
    deriv_path = parse_multipath(path_str) if path_str else None
    return deriv_path, ranged


class PubkeyProvider(object):
    """
    A public key expression in a descriptor.
    Can contain the key origin info, the pubkey itself, and subsequent derivation paths for derivation from the pubkey
    The pubkey can be a typical pubkey or an extended pubkey.
    """
    def __init__(
        self,
        origin: Optional['KeyOriginInfo'],
        pubkey: str,
        deriv_path: Optional[List[List[int]]],
        expr_index: int,
        ranged: bool
    ) -> None:
        """
        :param origin: The key origin if one is available
        :param pubkey: The public key. Either a hex string or a serialized extended pubkey
        :param deriv_path: Additional derivation path if the pubkey is an extended pubkey
        :param expr_index: The index of this key in the BIP 388 Key information vector.
            A key that appears multiple times in a descriptor uses the same index everywhere.
        """
        self.origin = origin
        self.pubkey = pubkey
        self.deriv_path = deriv_path
        self.expr_index = expr_index
        self.ranged = ranged
        self.multipath_len = max([len(p) for p in self.deriv_path]) if self.deriv_path is not None and len(self.deriv_path) > 0 else 1

        # Make ExtendedKey from pubkey if it isn't hex
        self.extkey = None
        try:
            unhexlify(self.pubkey)
            # Is hex, normal pubkey
        except Exception:
            # Not hex, maybe xpub
            self.extkey = ExtendedKey.deserialize(self.pubkey)

    @classmethod
    def parse(cls, s: str, key_expr_index: int) -> 'PubkeyProvider':
        """
        Deserialize a key expression from the string into a ``PubkeyProvider``.

        :param s: String containing the key expression
        :param key_expr_index: The position of this key within the descriptor
        :return: A new ``PubkeyProvider`` containing the details given by ``s``
        """
        origin = None
        deriv_path = None
        ranged = False

        if not s:
            raise ValueError("Empty key expression")
        if s[0] == "[":
            end = s.index("]")
            origin = KeyOriginInfo.from_string(s[1:end])
            s = s[end + 1:]

        pubkey = s
        slash_idx = s.find("/")
        if slash_idx != -1:
            pubkey = s[:slash_idx]
            deriv_path, ranged = _parse_ranged_deriv_path(s[slash_idx + 1:])

        return cls(origin, pubkey, deriv_path, key_expr_index, ranged)

    def to_string(self, hardened_char: str = "h") -> str:
        """
        Serialize the pubkey expression to a string to be used in a descriptor

        :return: The pubkey expression as a string
        """
        s = ""
        if self.origin:
            s += "[{}]".format(self.origin.to_string(hardened_char))
        s += self.pubkey
        if self.deriv_path:
            s += multipath_to_string(self.deriv_path, hardened_char)
        if self.ranged:
            s += "/*"
        return s

    def get_deriv_path(self, pos: int, multipath_pos: int) -> List[int]:
        path = []
        if self.deriv_path:
            for p in self.deriv_path:
                if len(p) == 1:
                    path.append(p[0])
                else:
                    path.append(p[multipath_pos])
        if self.ranged:
            path.append(pos)
        return path

    def get_pubkey_bytes(self, pos: int, multipath_pos: int = 0) -> bytes:
        if self.extkey is not None:
            if self.deriv_path is not None:
                path = self.get_deriv_path(pos, multipath_pos)
                child_key = self.extkey.derive_pub_path(path)
                return child_key.pubkey
            else:
                return self.extkey.pubkey
        return unhexlify(self.pubkey)

    def get_full_derivation_path(self, pos: int, multipath_pos: int = 0) -> str:
        """
        Returns the full derivation path at the given position, including the origin
        """
        path = self.origin.get_derivation_path() if self.origin is not None else "m/"
        if self.deriv_path:
            path += path_to_string(self.get_deriv_path(pos, multipath_pos))
        if self.ranged:
            path += str(pos)
        return path

    def get_full_derivation_int_list(self, pos: int, multipath_pos: int = 0) -> List[int]:
        """
        Returns the full derivation path as an integer list at the given position.
        Includes the origin and master key fingerprint as an int
        """
        path: List[int] = self.origin.get_full_int_list() if self.origin is not None else []
        if self.deriv_path:
            path.extend(self.get_deriv_path(pos, multipath_pos))
        if self.ranged:
            path.append(pos)
        return path

    def get_bip388_placeholder(self) -> str:
        """
        Get the key placeholder expression for this pubkey to be used in BIP 388 Wallet Policies.
        The descriptor will be first checked for whether it likely confirms to BIP 388. Specifically:

        - All pubkeys must be ranged
        - All multipath specifiers must be exactly 2 items.

        :return: The key placeholder expression
        :raises InvalidPolicyError: If the pubkey does not meet the requirements for a wallet policy as specified in BIP 388
        """
        self._check_bip388_deriv_path()
        return f"@{self.expr_index}{self._get_bip388_deriv_suffix()}"

    def _check_bip388_deriv_path(self) -> None:
        """
        :meta private:

        Check the BIP 388 requirements on this pubkey's derivation path.

        :raises InvalidPolicyError: If the pubkey does not meet the requirements for a wallet policy as specified in BIP 388
        """
        if not self.ranged:
            raise InvalidPolicyError("BIP 388 requires all pubkeys to be ranged")
        if self.multipath_len > 2:
            raise InvalidPolicyError("BIP 388 requires all multipath specifiers to be exactly 2 elements")

    def _get_bip388_deriv_suffix(self) -> str:
        """
        :meta private:

        Get the derivation path suffix for this pubkey's BIP 388 key placeholder expression.

        :return: The derivation path suffix, including the ``/*`` range marker
        """
        deriv_path = multipath_to_string(self.deriv_path, hardened_char="'") if self.deriv_path else ""
        return deriv_path + "/*"

    def get_bip388_key_info(self) -> str:
        """
        Serialize the pubkey expression to a string without the trailing derivation path.
        Used in the Key information vector of BIP 388 Wallet Policies.

        :return: The pubkey expression without trailing derivaiton path as a string
        :raises InvalidPolicyError: If the pubkey does not meet the requirements for a wallet policy as specified in BIP 388
        """
        s = ""
        if self.origin:
            s += "[{}]".format(self.origin.to_string("'"))
        s += self.pubkey
        return s

    def __lt__(self, other: 'PubkeyProvider') -> bool:
        return self.pubkey < other.pubkey


class MusigPubkeyProvider(PubkeyProvider):
    """
    A ``musig()`` aggregate key expression with a shared derivation path, as specified in BIP 390.
    """

    def __init__(
        self,
        participants: List['PubkeyProvider'],
        deriv_path: Optional[List[List[int]]],
        ranged: bool,
    ) -> None:
        r"""
        :param participants: The :class:`PubkeyProvider`\ s aggregated by this ``musig()`` expression
        :param deriv_path: Derivation path for the aggregate key
        :param ranged: Whether the aggregate key is ranged
        """
        super().__init__(None, "", deriv_path, participants[0].expr_index, ranged)
        self.participants = participants

    @classmethod
    def parse_musig(cls, s: str, key_expr_index: int) -> Tuple['MusigPubkeyProvider', int]:
        """
        Deserialize a ``musig()`` key expression from the string into a ``MusigPubkeyProvider``.

        :param s: String containing the ``musig()`` key expression
        :param key_expr_index: The position of the first participant key within the descriptor
        :return: A new ``MusigPubkeyProvider`` and the position of the next key expression
        :raises: ValueError: if the ``musig()`` key expression is malformed
        """
        func, expr = _get_func_expr(s)
        if func != "musig":
            raise ValueError(f"Expected musig() key expression, got {func}()")

        suffix = s[s.rindex(")") + 1:]
        deriv_path = None
        ranged = False
        if suffix:
            if not suffix.startswith("/"):
                raise ValueError("MuSig derivation path must begin with '/'")
            deriv_path, ranged = _parse_ranged_deriv_path(suffix[1:])

        for path in deriv_path or []:
            for step in path:
                if is_hardened(step):
                    raise ValueError("musig() cannot have hardened derivation steps")

        participants = []
        while expr:
            if expr.startswith("musig("):
                raise ValueError("musig() key expressions cannot be nested")
            participant, expr, key_expr_index = parse_pubkey(expr, key_expr_index)
            participants.append(participant)
        if len(participants) < 2:
            raise ValueError("musig() requires at least two participants")
        if deriv_path is not None or ranged:
            for participant in participants:
                if participant.extkey is None:
                    raise ValueError("musig() derivation requires extended public key participants")
                if participant.ranged or participant.multipath_len > 1:
                    raise ValueError("musig() participants cannot be ranged or multipath when musig() itself has a derivation path")
        return cls(participants, deriv_path, ranged), key_expr_index

    def to_string(self, hardened_char: str = "h") -> str:
        """
        Serialize the ``musig()`` expression to a string to be used in a descriptor

        :return: The ``musig()`` expression as a string
        """
        participants = ",".join(p.to_string(hardened_char) for p in self.participants)
        result = f"musig({participants})"
        if self.deriv_path:
            result += multipath_to_string(self.deriv_path, hardened_char)
        if self.ranged:
            result += "/*"
        return result

    def get_bip388_placeholder(self) -> str:
        """
        Get the key placeholder expression for this ``musig()`` expression to be used in BIP 388 Wallet Policies.

        :return: The key placeholder expression
        :raises InvalidPolicyError: If the aggregate key does not meet the requirements for a wallet policy as specified in BIP 388
        """
        self._check_bip388_deriv_path()
        for participant in self.participants:
            if participant.deriv_path is not None or participant.ranged:
                raise InvalidPolicyError("BIP 388 requires all derivation to follow musig() aggregation")
        participants = ",".join(f"@{p.expr_index}" for p in self.participants)
        return f"musig({participants}){self._get_bip388_deriv_suffix()}"

    def get_pubkey_bytes(self, pos: int, multipath_pos: int = 0) -> bytes:
        raise NotImplementedError("HWI cannot expand musig() aggregate keys")


class Descriptor(object):
    r"""
    An abstract class for Descriptors themselves.
    Descriptors can contain multiple :class:`PubkeyProvider`\ s and multiple ``Descriptor`` as subdescriptors.
    """
    def __init__(
        self,
        pubkeys: List['PubkeyProvider'],
        subdescriptors: List['Descriptor'],
        name: str
    ) -> None:
        r"""
        :param pubkeys: The :class:`PubkeyProvider`\ s that are part of this descriptor
        :param subdescriptor: The ``Descriptor``\ s that are part of this descriptor
        :param name: The name of the function for this descriptor
        """
        self.pubkeys = pubkeys
        self.subdescriptors = subdescriptors
        self.name = name

    def to_string_no_checksum(self, hardened_char: str = "h") -> str:
        """
        Serializes the descriptor as a string without the descriptor checksum

        :return: The descriptor string
        """
        return "{}({}{})".format(
            self.name,
            ",".join([p.to_string(hardened_char) for p in self.pubkeys]),
            self.subdescriptors[0].to_string_no_checksum(hardened_char) if len(self.subdescriptors) > 0 else ""
        )

    def to_string(self, hardened_char: str = "h") -> str:
        """
        Serializes the descriptor as a string with the checksum

        :return: The descriptor with a checksum
        """
        return AddChecksum(self.to_string_no_checksum(hardened_char))

    def get_address_type(self) -> Optional[AddressType]:
        """Return the address type, or ``None`` for descriptors without an address encoding."""
        return None

    def get_bip388_template(self) -> str:
        """
        Get the BIP 388 Wallet Descriptor Template string for this descriptor.

        Some BIP 388 specified checks are performed to determine. See ``get_bip388_placeholder()`` for the
        pubkey specific checks that are performed.

        Note that not all BIP 388 specified checks are performed, specifically the following checks are not performed:

        - Duplicate keys check
        - Disjoint multipath check

        :return: The template string
        :raises InvalidPolicyError: If the pubkey does not meet the requirements for a wallet policy as specified in BIP 388
        """
        return "{}({}{})".format(
            self.name,
            ",".join([p.get_bip388_placeholder() for p in self.pubkeys]),
            self.subdescriptors[0].get_bip388_template() if len(self.subdescriptors) > 0 else ""
        )

    def get_pubkey_providers(self) -> list['PubkeyProvider']:
        r"""
        Get the individual pubkey expressions contained in this descriptor, in the order in
        which they first appear in the descriptor string. A ``musig()`` aggregate key is
        replaced by its participant keys, and a key that appears more than once is returned
        only once, matching the BIP 388 Key information vector, so these can be used with
        :func:`get_bip388_template` to get a full BIP 388 Wallet Policy for this descriptor.

        :return: List of :class:`PubkeyProvider`\ s
        """
        out: Dict[str, 'PubkeyProvider'] = {}
        for pubkey in self.get_derivation_providers():
            participants = pubkey.participants if isinstance(pubkey, MusigPubkeyProvider) else [pubkey]
            for participant in participants:
                out.setdefault(participant.get_bip388_key_info(), participant)
        return list(out.values())

    def get_derivation_providers(self) -> list['PubkeyProvider']:
        r"""
        Get the key expressions contained in this descriptor whose derivation path suffixes
        belong to the descriptor, in the same order that they appear in the descriptor
        string, including keys that appear more than once. Unlike
        :func:`get_pubkey_providers`, a ``musig()`` aggregate key with its own derivation
        path suffix is returned as a single :class:`MusigPubkeyProvider`, since the suffix
        applies to the aggregate key. Participant keys are returned for a ``musig()``
        without a derivation path suffix, where any derivation happens on the participant
        keys before aggregation.

        :return: List of :class:`PubkeyProvider`\ s
        """
        out: list['PubkeyProvider'] = []
        for pubkey in self.pubkeys:
            if isinstance(pubkey, MusigPubkeyProvider) and pubkey.deriv_path is None and not pubkey.ranged:
                # Without an aggregate derivation path, derivation happens on the participant keys
                out.extend(pubkey.participants)
            else:
                out.append(pubkey)
        for subdescriptor in self.subdescriptors:
            out.extend(subdescriptor.get_derivation_providers())
        return out

    def derive(self, pos: int, multipath_index: int = 0) -> 'Descriptor':
        """Select a multipath entry and address index from a ranged descriptor."""

        descriptor = deepcopy(self)
        for pubkey in descriptor.get_derivation_providers():
            path = pubkey.get_deriv_path(pos, multipath_index)
            pubkey.deriv_path = [[step] for step in path] or None
            pubkey.ranged = False
            pubkey.multipath_len = 1
        return descriptor


class PKDescriptor(Descriptor):
    """
    A descriptor for ``pk()`` descriptors
    """
    def __init__(
        self,
        pubkey: 'PubkeyProvider'
    ) -> None:
        """
        :param pubkey: The :class:`PubkeyProvider` for this descriptor
        """
        super().__init__([pubkey], [], "pk")


class PKHDescriptor(Descriptor):
    """
    A descriptor for ``pkh()`` descriptors
    """
    def __init__(
        self,
        pubkey: 'PubkeyProvider'
    ) -> None:
        """
        :param pubkey: The :class:`PubkeyProvider` for this descriptor
        """
        super().__init__([pubkey], [], "pkh")

    def get_address_type(self) -> Optional[AddressType]:
        return AddressType.LEGACY


class WPKHDescriptor(Descriptor):
    """
    A descriptor for ``wpkh()`` descriptors
    """
    def __init__(
        self,
        pubkey: 'PubkeyProvider'
    ) -> None:
        """
        :param pubkey: The :class:`PubkeyProvider` for this descriptor
        """
        super().__init__([pubkey], [], "wpkh")

    def get_address_type(self) -> Optional[AddressType]:
        return AddressType.WIT


class MultisigDescriptor(Descriptor):
    """
    A descriptor for ``multi()`` and ``sortedmulti()`` descriptors
    """
    def __init__(
        self,
        pubkeys: List['PubkeyProvider'],
        thresh: int,
        is_sorted: bool
    ) -> None:
        r"""
        :param pubkeys: The :class:`PubkeyProvider`\ s for this descriptor
        :param thresh: The number of keys required to sign this multisig
        :param is_sorted: Whether this is a ``sortedmulti()`` descriptor
        """
        super().__init__(pubkeys, [], "sortedmulti" if is_sorted else "multi")
        self.thresh = thresh
        self.is_sorted = is_sorted

    def to_string_no_checksum(self, hardened_char: str = "h") -> str:
        return "{}({},{})".format(self.name, self.thresh, ",".join([p.to_string(hardened_char) for p in self.pubkeys]))

    def get_bip388_template(self) -> str:
        return "{}({},{})".format(self.name, self.thresh, ",".join([p.get_bip388_placeholder() for p in self.pubkeys]))


class SHDescriptor(Descriptor):
    """
    A descriptor for ``sh()`` descriptors
    """
    def __init__(
        self,
        subdescriptor: 'Descriptor'
    ) -> None:
        """
        :param subdescriptor: The :class:`Descriptor` that is a sub-descriptor for this descriptor
        """
        super().__init__([], [subdescriptor], "sh")

    def get_address_type(self) -> Optional[AddressType]:
        if self.subdescriptors[0].get_address_type() is AddressType.WIT:
            return AddressType.SH_WIT
        return AddressType.LEGACY


class WSHDescriptor(Descriptor):
    """
    A descriptor for ``wsh()`` descriptors
    """
    def __init__(
        self,
        subdescriptor: 'Descriptor'
    ) -> None:
        """
        :param subdescriptor: The :class:`Descriptor` that is a sub-descriptor for this descriptor
        """
        super().__init__([], [subdescriptor], "wsh")

    def get_address_type(self) -> Optional[AddressType]:
        return AddressType.WIT


class TRDescriptor(Descriptor):
    """
    A descriptor for ``tr()`` descriptors
    """
    def __init__(
        self,
        internal_key: 'PubkeyProvider',
        subdescriptors: List['Descriptor'] = [],
        depths: List[int] = []
    ) -> None:
        r"""
        :param internal_key: The :class:`PubkeyProvider` that is the internal key for this descriptor
        :param subdescriptors: The :class:`Descriptor`\ s that are the leaf scripts for this descriptor
        :param depths: The depths of the leaf scripts in the same order as `subdescriptors`
        """
        super().__init__([internal_key], subdescriptors, "tr")
        self.depths = depths

    def get_address_type(self) -> Optional[AddressType]:
        return AddressType.TAP

    def to_string_no_checksum(self, hardened_char: str = "h") -> str:
        r = f"{self.name}({self.pubkeys[0].to_string(hardened_char)}"
        path: List[bool] = [] # Track left or right for each depth
        for p, depth in enumerate(self.depths):
            r += ","
            while len(path) <= depth:
                if len(path) > 0:
                    r += "{"
                path.append(False)
            r += self.subdescriptors[p].to_string_no_checksum(hardened_char)
            while len(path) > 0 and path[-1]:
                if len(path) > 0:
                    r += "}"
                path.pop()
            if len(path) > 0:
                path[-1] = True
        r += ")"
        return r

    def get_bip388_template(self) -> str:
        r = f"{self.name}({self.pubkeys[0].get_bip388_placeholder()}"
        path: List[bool] = [] # Track left or right for each depth
        for p, depth in enumerate(self.depths):
            r += ","
            while len(path) <= depth:
                if len(path) > 0:
                    r += "{"
                path.append(False)
            r += self.subdescriptors[p].get_bip388_template()
            while len(path) > 0 and path[-1]:
                if len(path) > 0:
                    r += "}"
                path.pop()
            if len(path) > 0:
                path[-1] = True
        r += ")"
        return r


class MiniscriptDescriptor(Descriptor):
    """
    A Miniscript expression contained in a descriptor
    """

    def __init__(
        self,
        wrappers: str,
        name: str,
        args: List[Union[str, 'PubkeyProvider', 'MiniscriptDescriptor']]
    ) -> None:
        """
        :param wrappers: The Miniscript wrappers applied to this fragment, without the ``:`` separator
        :param name: The name of the Miniscript fragment
        :param args: The fragment arguments: key expressions, nested Miniscript expressions,
            and verbatim strings for numbers and hashes
        """
        pubkeys = [arg for arg in args if isinstance(arg, PubkeyProvider)]
        subdescriptors: List[Descriptor] = [arg for arg in args if isinstance(arg, MiniscriptDescriptor)]
        super().__init__(pubkeys, subdescriptors, name)
        self.wrappers = wrappers
        self.args = args

    def _serialize(self, serialize_arg: Callable[[Union[str, 'PubkeyProvider', 'MiniscriptDescriptor']], str]) -> str:
        prefix = f"{self.wrappers}:" if self.wrappers else ""
        if not self.args:
            return prefix + self.name
        return "{}{}({})".format(prefix, self.name, ",".join(serialize_arg(arg) for arg in self.args))

    def to_string_no_checksum(self, hardened_char: str = "h") -> str:
        def serialize_arg(arg: Union[str, 'PubkeyProvider', 'MiniscriptDescriptor']) -> str:
            if isinstance(arg, MiniscriptDescriptor):
                return arg.to_string_no_checksum(hardened_char)
            if isinstance(arg, PubkeyProvider):
                return arg.to_string(hardened_char)
            return arg
        return self._serialize(serialize_arg)

    def get_bip388_template(self) -> str:
        def serialize_arg(arg: Union[str, 'PubkeyProvider', 'MiniscriptDescriptor']) -> str:
            if isinstance(arg, MiniscriptDescriptor):
                return arg.get_bip388_template()
            if isinstance(arg, PubkeyProvider):
                return arg.get_bip388_placeholder()
            return arg
        return self._serialize(serialize_arg)


def _get_func_expr(s: str) -> Tuple[str, str]:
    """
    Get the function name and then the expression inside

    :param s: The string that begins with a function name
    :return: The function name as the first element of the tuple, and the expression contained within the function as the second element
    :raises: ValueError: if a matching pair of parentheses cannot be found
    """
    try:
        start = s.index("(")
        end = s.rindex(")")
        return s[0:start], s[start + 1:end]
    except ValueError:
        raise ValueError("A matching pair of parentheses cannot be found")


def _get_const(s: str, const: str) -> str:
    """
    Get the first character of the string, make sure it is the expected character,
    and return the rest of the string

    :param s: The string that begins with a constant character
    :param const: The constant character
    :return: The remainder of the string without the constant character
    :raises: ValueError: if the first character is not the constant character
    """
    if not s:
        raise ValueError(f"Expected '{const}' but reached the end")
    if s[0] != const:
        raise ValueError(f"Expected '{const}' but got '{s[0]}'")
    return s[1:]


def _get_expr(s: str) -> Tuple[str, str]:
    """
    Extract the expression that ``s`` begins with.

    This will return the initial part of ``s``, up to the first comma or closing brace,
    skipping ones that are surrounded by braces.

    :param s: The string to extract the expression from
    :return: A pair with the first item being the extracted expression and the second the rest of the string
    """
    level: int = 0
    for i, c in enumerate(s):
        if c in ["(", "{"]:
            level += 1
        elif level > 0 and c in [")", "}"]:
            level -= 1
        elif level == 0 and c in [")", "}", ","]:
            break
    else:
        return s, ""
    return s[0:i], s[i:]

def parse_pubkey(expr: str, key_expr_index: int) -> Tuple['PubkeyProvider', str, int]:
    """
    Parses an individual pubkey expression from a string that may contain more than one pubkey expression.

    :param expr: The expression to parse a pubkey expression from
    :param key_expr_index: The position of the next key to be parsed
    :return: The :class:`PubkeyProvider` that is parsed as the first item of a tuple, the remainder of the expression as the second item, and the index of the next key expression as the third.
    """
    end = len(expr)
    comma_idx = expr.find(",")
    next_expr = ""
    if comma_idx != -1:
        end = comma_idx
        next_expr = expr[end + 1:]
        if not next_expr:
            raise ValueError("Trailing comma after key expression")
    return PubkeyProvider.parse(expr[:end], key_expr_index), next_expr, (key_expr_index + 1)


class _ParseDescriptorContext(Enum):
    """
    :meta private:

    Enum representing the level that we are in when parsing a descriptor.
    Some expressions aren't allowed at certain levels, this helps us track those.
    """

    TOP = 1
    """The top level, not within any descriptor"""

    P2SH = 2
    """Within a ``sh()`` descriptor"""

    P2WSH = 3
    """Within a ``wsh()`` descriptor"""

class _MiniscriptContext(Enum):
    """
    :meta private:

    Enum representing the script version used to interpret a Miniscript expression.
    """

    SEGWIT_V0 = 1
    """A Segwit v0 witness script"""

    TAPSCRIPT = 2
    """A Taproot leaf script"""


def _parse_miniscript_num(name: str, arg: str) -> int:
    if not arg.isdigit():
        raise ValueError(f"{name}() argument must be a number, got {arg}")
    return int(arg)


def _parse_miniscript(
    expr: str,
    key_expr_index: int,
    ctx: '_MiniscriptContext',
) -> Tuple['MiniscriptDescriptor', int]:
    """
    :meta private:

    Parse a Miniscript expression. Only the structure of the expression is
    validated; Miniscript type checking is left to the device.

    :param expr: The Miniscript expression to parse
    :param key_expr_index: The position of the next key expression within the descriptor
    :param ctx: The script version used to interpret the Miniscript expression
    :return: The parsed :class:`MiniscriptDescriptor` and the position of the next key expression
    :raises: ValueError: if the Miniscript expression is malformed
    """
    wrappers = ""
    paren_idx = expr.find("(")
    colon_idx = expr.find(":")
    if colon_idx != -1 and (paren_idx == -1 or colon_idx < paren_idx):
        wrappers = expr[:colon_idx]
        expr = expr[colon_idx + 1:]
        if not wrappers:
            raise ValueError("Missing Miniscript wrapper before ':'")
        for wrapper in wrappers:
            if wrapper not in _MINISCRIPT_WRAPPERS:
                raise ValueError(f"Unknown Miniscript wrapper: {wrapper}")
        paren_idx = expr.find("(")

    if expr in ("0", "1"):
        return MiniscriptDescriptor(wrappers, expr, []), key_expr_index

    if paren_idx == -1 or not expr.endswith(")"):
        raise ValueError(f"Invalid Miniscript expression: {expr}")
    name = expr[:paren_idx]

    arg_strs = []
    rest = expr[paren_idx + 1:-1]
    while rest:
        arg, rest = _get_expr(rest)
        if not arg:
            raise ValueError(f"Empty argument in {name}()")
        arg_strs.append(arg)
        if rest:
            rest = _get_const(rest, ",")
            if not rest:
                raise ValueError(f"Trailing comma in {name}()")

    args: List[Union[str, 'PubkeyProvider', 'MiniscriptDescriptor']] = []
    if name in _MINISCRIPT_KEY_FRAGMENTS:
        if len(arg_strs) != 1:
            raise ValueError(f"{name}() takes exactly one key expression")
        if ctx != _MiniscriptContext.TAPSCRIPT and arg_strs[0].startswith("musig("):
            raise ValueError("musig() is only allowed in tapscript Miniscript")
        key, key_expr_index = _parse_key_expr(arg_strs[0], key_expr_index)
        args.append(key)
    elif name == "multi":
        if ctx != _MiniscriptContext.SEGWIT_V0:
            raise ValueError("multi() is only allowed in Segwit v0 Miniscript")
        if len(arg_strs) < 2:
            raise ValueError("multi() takes a threshold and at least one key expression")
        if len(arg_strs) - 1 > 20:
            raise ValueError("multi() supports at most 20 keys")
        thresh = _parse_miniscript_num(name, arg_strs[0])
        if not 1 <= thresh <= len(arg_strs) - 1:
            raise ValueError("multi() threshold must be between 1 and the number of keys")
        args.append(arg_strs[0])
        for arg_str in arg_strs[1:]:
            args.append(PubkeyProvider.parse(arg_str, key_expr_index))
            key_expr_index += 1
    elif name in _MINISCRIPT_TAPSCRIPT_MULTI_FRAGMENTS:
        if ctx != _MiniscriptContext.TAPSCRIPT:
            raise ValueError(f"{name}() is only allowed in tapscript Miniscript")
        if len(arg_strs) < 2:
            raise ValueError(f"{name}() takes a threshold and at least one key expression")
        if len(arg_strs) - 1 > 999:
            raise ValueError(f"{name}() supports at most 999 keys")
        thresh = _parse_miniscript_num(name, arg_strs[0])
        if not 1 <= thresh <= len(arg_strs) - 1:
            raise ValueError(f"{name}() threshold must be between 1 and the number of keys")
        args.append(arg_strs[0])
        for arg_str in arg_strs[1:]:
            key, key_expr_index = _parse_key_expr(arg_str, key_expr_index)
            args.append(key)
    elif name in _MINISCRIPT_TIMELOCK_FRAGMENTS:
        if len(arg_strs) != 1:
            raise ValueError(f"{name}() takes exactly one number")
        locktime = _parse_miniscript_num(name, arg_strs[0])
        if not 1 <= locktime < 2**31:
            raise ValueError(f"{name}() locktime must be between 1 and 2**31 - 1")
        args.append(arg_strs[0])
    elif name in _MINISCRIPT_HASH_FRAGMENTS:
        if len(arg_strs) != 1:
            raise ValueError(f"{name}() takes exactly one hash")
        hash_len = _MINISCRIPT_HASH_FRAGMENTS[name]
        try:
            hash_bytes = unhexlify(arg_strs[0])
        except Exception:
            raise ValueError(f"{name}() takes a {hash_len} character hex string")
        if len(hash_bytes) * 2 != hash_len:
            raise ValueError(f"{name}() takes a {hash_len} character hex string")
        args.append(arg_strs[0])
    elif name == "andor" or name in _MINISCRIPT_BINARY_FRAGMENTS:
        num_args = 3 if name == "andor" else 2
        if len(arg_strs) != num_args:
            raise ValueError(f"{name}() takes exactly {num_args} Miniscript expressions")
        for arg_str in arg_strs:
            sub, key_expr_index = _parse_miniscript(arg_str, key_expr_index, ctx)
            args.append(sub)
    elif name == "thresh":
        if len(arg_strs) < 2:
            raise ValueError("thresh() takes a threshold and at least one Miniscript expression")
        thresh = _parse_miniscript_num(name, arg_strs[0])
        if not 1 <= thresh <= len(arg_strs) - 1:
            raise ValueError("thresh() threshold must be between 1 and the number of subexpressions")
        args.append(arg_strs[0])
        for arg_str in arg_strs[1:]:
            sub, key_expr_index = _parse_miniscript(arg_str, key_expr_index, ctx)
            args.append(sub)
    else:
        raise ValueError(f"Unknown Miniscript fragment: {name}")

    return MiniscriptDescriptor(wrappers, name, args), key_expr_index


def _parse_key_expr(expr: str, key_expr_index: int) -> Tuple['PubkeyProvider', int]:
    """
    :meta private:

    Parse a single key expression, which may be a ``musig()`` aggregate key.

    :param expr: The key expression to parse
    :param key_expr_index: The position of the key within the descriptor
    :return: The parsed :class:`PubkeyProvider` and the position of the next key expression
    :raises: ValueError: if the key expression is malformed
    """
    if expr.startswith("musig("):
        return MusigPubkeyProvider.parse_musig(expr, key_expr_index)
    return PubkeyProvider.parse(expr, key_expr_index), key_expr_index + 1


def _parse_descriptor(desc: str, ctx: '_ParseDescriptorContext', key_expr_index: int) -> Tuple['Descriptor', int]:
    """
    :meta private:

    Parse a descriptor given the context level we are in.
    Used recursively to parse subdescriptors

    :param desc: The descriptor string to parse
    :param ctx: The :class:`_ParseDescriptorContext` indicating the level we are in
    :param key_expr_index: The position of the next key to be parsed within the descriptor
    :return: The parsed descriptor as the first item, and the index of the next key expression as the second.
    :raises: ValueError: if the descriptor is malformed
    """
    try:
        func, expr = _get_func_expr(desc)
    except ValueError:
        if ctx == _ParseDescriptorContext.P2WSH:
            return _parse_miniscript(desc, key_expr_index, _MiniscriptContext.SEGWIT_V0)
        raise
    if func == "pk":
        if expr.startswith("musig("):
            raise ValueError("musig() is only allowed in tr() descriptors")
        pubkey, expr, key_expr_index = parse_pubkey(expr, key_expr_index)
        if expr:
            raise ValueError("more than one pubkey in pk descriptor")
        return PKDescriptor(pubkey), key_expr_index
    if func == "pkh":
        if not (ctx == _ParseDescriptorContext.TOP or ctx == _ParseDescriptorContext.P2SH or ctx == _ParseDescriptorContext.P2WSH):
            raise ValueError("Can only have pkh at top level, in sh(), or in wsh()")
        if expr.startswith("musig("):
            raise ValueError("musig() is only allowed in tr() descriptors")
        pubkey, expr, key_expr_index = parse_pubkey(expr, key_expr_index)
        if expr:
            raise ValueError("More than one pubkey in pkh descriptor")
        return PKHDescriptor(pubkey), key_expr_index
    if func == "sortedmulti" or func == "multi":
        if not (ctx == _ParseDescriptorContext.TOP or ctx == _ParseDescriptorContext.P2SH or ctx == _ParseDescriptorContext.P2WSH):
            raise ValueError("Can only have multi/sortedmulti at top level, in sh(), or in wsh()")
        is_sorted = func == "sortedmulti"
        comma_idx = expr.index(",")
        thresh = int(expr[:comma_idx])
        expr = expr[comma_idx + 1:]
        pubkeys = []
        multipath_len = None
        while expr:
            pubkey, expr, key_expr_index = parse_pubkey(expr, key_expr_index)
            if pubkey.multipath_len > 1:
                if multipath_len is None:
                    multipath_len = pubkey.multipath_len
                elif multipath_len != pubkey.multipath_len:
                    raise ValueError("Mismatched multipath paths")
            pubkeys.append(pubkey)
        if len(pubkeys) == 0 or len(pubkeys) > 16:
            raise ValueError("Cannot have {} keys in a multisig; must have between 1 and 16 keys, inclusive".format(len(pubkeys)))
        elif thresh < 1:
            raise ValueError("Multisig threshold cannot be {}, must be at least 1".format(thresh))
        elif thresh > len(pubkeys):
            raise ValueError("Multisig threshold cannot be larger than the number of keys; threshold is {} but only {} keys specified".format(thresh, len(pubkeys)))
        if ctx == _ParseDescriptorContext.TOP and len(pubkeys) > 3:
            raise ValueError("Cannot have {} pubkeys in bare multisig: only at most 3 pubkeys")
        return MultisigDescriptor(pubkeys, thresh, is_sorted), key_expr_index
    if func == "wpkh":
        if not (ctx == _ParseDescriptorContext.TOP or ctx == _ParseDescriptorContext.P2SH):
            raise ValueError("Can only have wpkh() at top level or inside sh()")
        if expr.startswith("musig("):
            raise ValueError("musig() is only allowed in tr() descriptors")
        pubkey, expr, key_expr_index = parse_pubkey(expr, key_expr_index)
        if expr:
            raise ValueError("More than one pubkey in pkh descriptor")
        return WPKHDescriptor(pubkey), key_expr_index
    if func == "sh":
        if ctx != _ParseDescriptorContext.TOP:
            raise ValueError("Can only have sh() at top level")
        subdesc, key_expr_index = _parse_descriptor(expr, _ParseDescriptorContext.P2SH, key_expr_index)
        return SHDescriptor(subdesc), key_expr_index
    if func == "wsh":
        if not (ctx == _ParseDescriptorContext.TOP or ctx == _ParseDescriptorContext.P2SH):
            raise ValueError("Can only have wsh() at top level or inside sh()")
        subdesc, key_expr_index = _parse_descriptor(expr, _ParseDescriptorContext.P2WSH, key_expr_index)
        return WSHDescriptor(subdesc), key_expr_index
    if func == "tr":
        if ctx != _ParseDescriptorContext.TOP:
            raise ValueError("Can only have tr at top level")
        multipath_len = None
        internal_expr, expr = _get_expr(expr)
        internal_key, key_expr_index = _parse_key_expr(internal_expr, key_expr_index)
        if internal_key.multipath_len > 1:
            multipath_len = internal_key.multipath_len
        subscripts: List[Descriptor] = []
        depths = []
        if expr:
            expr = _get_const(expr, ",")
            # Path from top of the tree to what we're currently processing.
            # branches[i] == False: left branch in the i'th step from the top
            # branches[i] == true: right branch
            branches = []
            while True:
                # Process open braces
                while True:
                    try:
                        expr = _get_const(expr, "{")
                        branches.append(False)
                    except ValueError:
                        break
                    if len(branches) > MAX_TAPROOT_NODES:
                        raise ValueError("tr() supports at most {MAX_TAPROOT_NODES} nesting levels")
                # Process script expression
                sarg, expr = _get_expr(expr)
                subdesc, key_expr_index = _parse_miniscript(
                    sarg,
                    key_expr_index,
                    _MiniscriptContext.TAPSCRIPT,
                )
                for pub in subdesc.get_derivation_providers():
                    if pub.multipath_len > 1:
                        if multipath_len is None:
                            multipath_len = pub.multipath_len
                        elif multipath_len != pub.multipath_len:
                            raise ValueError("Mismatched multipath paths")
                subscripts.append(subdesc)
                depths.append(len(branches))
                # Process closing braces
                while len(branches) > 0 and branches[-1]:
                    expr = _get_const(expr, "}")
                    branches.pop()
                # If we're at the end of a left branch, expect a comma
                if len(branches) > 0 and not branches[-1]:
                    expr = _get_const(expr, ",")
                    branches[-1] = True

                if len(branches) == 0:
                    break
        return TRDescriptor(internal_key, subscripts, depths), key_expr_index
    if ctx == _ParseDescriptorContext.P2SH:
        raise ValueError("A function is needed within P2SH")
    elif ctx == _ParseDescriptorContext.P2WSH:
        return _parse_miniscript(desc, key_expr_index, _MiniscriptContext.SEGWIT_V0)
    raise ValueError("{} is not a valid descriptor function".format(func))


def parse_descriptor(desc: str) -> 'Descriptor':
    """
    Parse a descriptor string into a :class:`Descriptor`.
    Validates the checksum if one is provided in the string

    :param desc: The descriptor string
    :return: The parsed :class:`Descriptor`
    :raises: ValueError: if the descriptor string is malformed
    """
    i = desc.find("#")
    if i != -1:
        checksum = desc[i + 1:]
        desc = desc[:i]
        computed = DescriptorChecksum(desc)
        if computed != checksum:
            raise ValueError("The checksum does not match; Got {}, expected {}".format(checksum, computed))
    descriptor = _parse_descriptor(desc, _ParseDescriptorContext.TOP, 0)[0]

    # A key that appears more than once must use a single index in the
    # BIP 388 Key information vector.
    indexes: Dict[str, int] = {}
    for pubkey in descriptor.get_derivation_providers():
        participants = pubkey.participants if isinstance(pubkey, MusigPubkeyProvider) else [pubkey]
        for participant in participants:
            participant.expr_index = indexes.setdefault(participant.get_bip388_key_info(), len(indexes))
    return descriptor

class RegisteredDescriptor:
    """
    An object containing a policy that was registered with a device
    """

    REG_VERSION = 0x00
    REG_NAME = 0x01
    REG_DESCRIPTOR = 0x02
    REG_DEVICE_TYPE = 0x03
    REG_REGISTRATION = 0x04

    def __init__(self, name: str, descriptor: Descriptor, device_type: str, registration: bytes) -> None:
        self.version = 1
        self.name = name
        self.descriptor = descriptor
        self.device_type = device_type
        self.registration = registration

    def serialize(self) -> str:
        r = b"rdesc"

        r += ser_compact_size(self.version)
        r += ser_string(self.name.encode())
        r += ser_string(self.descriptor.to_string().encode())
        r += ser_string(self.device_type.encode())
        r += ser_string(self.registration)

        return b64encode(r).decode()

    @classmethod
    def deserialize(cls, policy: str) -> 'RegisteredDescriptor':
        policy_bytes = b64decode(policy.strip())
        s = BufferedReader(BytesIO(policy_bytes))  # type: ignore

        magic = s.read(5)
        if magic != b"rdesc":
            raise BadArgumentError("Policy has invalid magic bytes")

        version = deser_compact_size(s)

        if version != 1:
            raise BadArgumentError("Serialized policy registration has unknown version number")

        name = deser_string(s).decode()
        descriptor = parse_descriptor(deser_string(s).decode())
        device_type = deser_string(s).decode()
        registration = deser_string(s)

        return cls(name, descriptor, device_type, registration)
