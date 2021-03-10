"""
Output Script Descriptors
*************************

HWI has a more limited implementation of descriptors.
See `Bitcoin Core's documentation <https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md>`_ for more details on descriptors.

This implementation only supports ``sh()``, ``wsh()``, ``pkh()``, ``wpkh()``, ``multi()``, and ``sortedmulti()`` descriptors.
Descriptors can be parsed, however the actual scripts are not generated.
"""


from .key import ExtendedKey, KeyOriginInfo, parse_path
from .common import hash160, sha256

from binascii import unhexlify
from collections import namedtuple
from enum import Enum
from typing import (
    List,
    Optional,
    Tuple,
)


ExpandedScripts = namedtuple("ExpandedScripts", ["output_script", "redeem_script", "witness_script"])

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
        deriv_path: Optional[str]
    ) -> None:
        """
        :param origin: The key origin if one is available
        :param pubkey: The public key. Either a hex string or a serialized extended pubkey
        :param deriv_path: Additional derivation path if the pubkey is an extended pubkey
        """
        self.origin = origin
        self.pubkey = pubkey
        self.deriv_path = deriv_path

        # Make ExtendedKey from pubkey if it isn't hex
        self.extkey = None
        try:
            unhexlify(self.pubkey)
            # Is hex, normal pubkey
        except Exception:
            # Not hex, maybe xpub
            self.extkey = ExtendedKey.deserialize(self.pubkey)

    @classmethod
    def parse(cls, s: str) -> 'PubkeyProvider':
        """
        Deserialize a key expression from the string into a ``PubkeyProvider``.

        :param s: String containing the key expression
        :return: A new ``PubkeyProvider`` containing the details given by ``s``
        """
        origin = None
        deriv_path = None

        if s[0] == "[":
            end = s.index("]")
            origin = KeyOriginInfo.from_string(s[1:end])
            s = s[end + 1:]

        pubkey = s
        slash_idx = s.find("/")
        if slash_idx != -1:
            pubkey = s[:slash_idx]
            deriv_path = s[slash_idx:]

        return cls(origin, pubkey, deriv_path)

    def to_string(self) -> str:
        """
        Serialize the pubkey expression to a string to be used in a descriptor

        :return: The pubkey expression as a string
        """
        s = ""
        if self.origin:
            s += "[{}]".format(self.origin.to_string())
        s += self.pubkey
        if self.deriv_path:
            s += self.deriv_path
        return s

    def get_pubkey_bytes(self, pos: int) -> bytes:
        if self.extkey is not None:
            if self.deriv_path is not None:
                path_str = self.deriv_path[1:]
                if path_str[-1] == "*":
                    path_str = path_str[-1] + str(pos)
                path = parse_path(path_str)
                child_key = self.extkey.derive_pub_path(path)
                return child_key.pubkey
            else:
                return self.extkey.pubkey
        return unhexlify(self.pubkey)

    def get_full_derivation_path(self, pos: int) -> str:
        """
        Returns the full derivation path at the given position, including the origin
        """
        path = self.origin.get_derivation_path() if self.origin is not None else "m/"
        path += self.deriv_path if self.deriv_path is not None else ""
        if path[-1] == "*":
            path = path[:-1] + str(pos)
        return path

    def get_full_derivation_int_list(self, pos: int) -> List[int]:
        """
        Returns the full derivation path as an integer list at the given position.
        Includes the origin and master key fingerprint as an int
        """
        path: List[int] = self.origin.get_full_int_list() if self.origin is not None else []
        if self.deriv_path is not None:
            der_split = self.deriv_path.split("/")
            for p in der_split:
                if not p:
                    continue
                if p == "*":
                    i = pos
                elif p[-1] in "'phHP":
                    assert len(p) >= 2
                    i = int(p[:-1]) | 0x80000000
                else:
                    i = int(p)
                path.append(i)
        return path

    def __lt__(self, other: 'PubkeyProvider') -> bool:
        return self.pubkey < other.pubkey


class Descriptor(object):
    r"""
    An abstract class for Descriptors themselves.
    Descriptors can contain multiple :class:`PubkeyProvider`\ s and no more than one ``Descriptor`` as a subdescriptor.
    """
    def __init__(
        self,
        pubkeys: List['PubkeyProvider'],
        subdescriptor: Optional['Descriptor'],
        name: str
    ) -> None:
        r"""
        :param pubkeys: The :class:`PubkeyProvider`\ s that are part of this descriptor
        :param subdescriptor: The ``Descriptor`` that is part of this descriptor
        :param name: The name of the function for this descriptor
        """
        self.pubkeys = pubkeys
        self.subdescriptor = subdescriptor
        self.name = name

    def to_string_no_checksum(self) -> str:
        """
        Serializes the descriptor as a string without the descriptor checksum

        :return: The descriptor string
        """
        return "{}({}{})".format(
            self.name,
            ",".join([p.to_string() for p in self.pubkeys]),
            self.subdescriptor.to_string_no_checksum() if self.subdescriptor else ""
        )

    def to_string(self) -> str:
        """
        Serializes the descriptor as a string wtih the checksum

        :return: The descriptor with a checksum
        """
        return AddChecksum(self.to_string_no_checksum())

    def expand(self, pos: int) -> "ExpandedScripts":
        """
        Returns the scripts for a descriptor at the given `pos` for ranged descriptors.
        """
        raise NotImplementedError("The Descriptor base class does not implement this method")


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
        super().__init__([pubkey], None, "pkh")

    def expand(self, pos: int) -> "ExpandedScripts":
        script = b"\x76\xa9\x14" + hash160(self.pubkeys[0].get_pubkey_bytes(pos)) + b"\x88\xac"
        return ExpandedScripts(script, None, None)


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
        super().__init__([pubkey], None, "wpkh")

    def expand(self, pos: int) -> "ExpandedScripts":
        script = b"\x00\x14" + hash160(self.pubkeys[0].get_pubkey_bytes(pos))
        return ExpandedScripts(script, None, None)


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
        super().__init__(pubkeys, None, "sortedmulti" if is_sorted else "multi")
        self.thresh = thresh
        self.is_sorted = is_sorted
        if self.is_sorted:
            self.pubkeys.sort()

    def to_string_no_checksum(self) -> str:
        return "{}({},{})".format(self.name, self.thresh, ",".join([p.to_string() for p in self.pubkeys]))

    def expand(self, pos: int) -> "ExpandedScripts":
        if self.thresh > 16:
            m = b"\x01" + self.thresh.to_bytes(1, "big")
        else:
            m = (self.thresh + 0x50).to_bytes(1, "big") if self.thresh > 0 else b"\x00"
        n = (len(self.pubkeys) + 0x50).to_bytes(1, "big") if len(self.pubkeys) > 0 else b"\x00"
        script: bytes = m
        der_pks = [p.get_pubkey_bytes(pos) for p in self.pubkeys]
        if self.is_sorted:
            der_pks.sort()
        for pk in der_pks:
            script += len(pk).to_bytes(1, "big") + pk
        script += n + b"\xae"

        return ExpandedScripts(script, None, None)


class SHDescriptor(Descriptor):
    """
    A descriptor for ``sh()`` descriptors
    """
    def __init__(
        self,
        subdescriptor: Optional['Descriptor']
    ) -> None:
        """
        :param subdescriptor: The :class:`Descriptor` that is a sub-descriptor for this descriptor
        """
        super().__init__([], subdescriptor, "sh")

    def expand(self, pos: int) -> "ExpandedScripts":
        assert self.subdescriptor
        redeem_script, _, witness_script = self.subdescriptor.expand(pos)
        script = b"\xa9\x14" + hash160(redeem_script) + b"\x87"
        return ExpandedScripts(script, redeem_script, witness_script)


class WSHDescriptor(Descriptor):
    """
    A descriptor for ``wsh()`` descriptors
    """
    def __init__(
        self,
        subdescriptor: Optional['Descriptor']
    ) -> None:
        """
        :param pubkey: The :class:`Descriptor` that is a sub-descriptor for this descriptor
        """
        super().__init__([], subdescriptor, "wsh")

    def expand(self, pos: int) -> "ExpandedScripts":
        assert self.subdescriptor
        witness_script, _, _ = self.subdescriptor.expand(pos)
        script = b"\x00\x20" + sha256(witness_script)
        return ExpandedScripts(script, None, witness_script)


def _get_func_expr(s: str) -> Tuple[str, str]:
    """
    Get the function name and then the expression inside

    :param s: The string that begins with a function name
    :return: The function name as the first element of the tuple, and the expression contained within the function as the second element
    :raises: ValueError: if a matching pair of parentheses cannot be found
    """
    start = s.index("(")
    end = s.rindex(")")
    return s[0:start], s[start + 1:end]


def parse_pubkey(expr: str) -> Tuple['PubkeyProvider', str]:
    """
    Parses an individual pubkey expression from a string that may contain more than one pubkey expression.

    :param expr: The expression to parse a pubkey expression from
    :return: The :class:`PubkeyProvider` that is parsed as the first item of a tuple, and the remainder of the expression as the second item.
    """
    end = len(expr)
    comma_idx = expr.find(",")
    next_expr = ""
    if comma_idx != -1:
        end = comma_idx
        next_expr = expr[end + 1:]
    return PubkeyProvider.parse(expr[:end]), next_expr


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


def _parse_descriptor(desc: str, ctx: '_ParseDescriptorContext') -> 'Descriptor':
    """
    :meta private:

    Parse a descriptor given the context level we are in.
    Used recursively to parse subdescriptors

    :param desc: The descriptor string to parse
    :param ctx: The :class:`_ParseDescriptorContext` indicating the level we are in
    :return: The parsed descriptor
    :raises: ValueError: if the descriptor is malformed
    """
    func, expr = _get_func_expr(desc)
    if func == "pkh":
        pubkey, expr = parse_pubkey(expr)
        if expr:
            raise ValueError("More than one pubkey in pkh descriptor")
        return PKHDescriptor(pubkey)
    if func == "sortedmulti" or func == "multi":
        is_sorted = func == "sortedmulti"
        comma_idx = expr.index(",")
        thresh = int(expr[:comma_idx])
        expr = expr[comma_idx + 1:]
        pubkeys = []
        while expr:
            pubkey, expr = parse_pubkey(expr)
            pubkeys.append(pubkey)
        if len(pubkeys) == 0 or len(pubkeys) > 16:
            raise ValueError("Cannot have {} keys in a multisig; must have between 1 and 16 keys, inclusive".format(len(pubkeys)))
        elif thresh < 1:
            raise ValueError("Multisig threshold cannot be {}, must be at least 1".format(thresh))
        elif thresh > len(pubkeys):
            raise ValueError("Multisig threshold cannot be larger than the number of keys; threshold is {} but only {} keys specified".format(thresh, len(pubkeys)))
        if ctx == _ParseDescriptorContext.TOP and len(pubkeys) > 3:
            raise ValueError("Cannot have {} pubkeys in bare multisig: only at most 3 pubkeys")
        return MultisigDescriptor(pubkeys, thresh, is_sorted)
    if ctx != _ParseDescriptorContext.P2WSH and func == "wpkh":
        pubkey, expr = parse_pubkey(expr)
        if expr:
            raise ValueError("More than one pubkey in pkh descriptor")
        return WPKHDescriptor(pubkey)
    elif ctx == _ParseDescriptorContext.P2WSH and func == "wpkh":
        raise ValueError("Cannot have wpkh within wsh")
    if ctx == _ParseDescriptorContext.TOP and func == "sh":
        subdesc = _parse_descriptor(expr, _ParseDescriptorContext.P2SH)
        return SHDescriptor(subdesc)
    elif ctx != _ParseDescriptorContext.TOP and func == "sh":
        raise ValueError("Cannot have sh in non-top level")
    if ctx != _ParseDescriptorContext.P2WSH and func == "wsh":
        subdesc = _parse_descriptor(expr, _ParseDescriptorContext.P2WSH)
        return WSHDescriptor(subdesc)
    elif ctx == _ParseDescriptorContext.P2WSH and func == "wsh":
        raise ValueError("Cannot have wsh within wsh")
    if ctx == _ParseDescriptorContext.P2SH:
        raise ValueError("A function is needed within P2SH")
    elif ctx == _ParseDescriptorContext.P2WSH:
        raise ValueError("A function is needed within P2WSH")
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
    return _parse_descriptor(desc, _ParseDescriptorContext.TOP)
