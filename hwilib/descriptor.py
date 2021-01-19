from .key import KeyOriginInfo

from enum import Enum
from typing import (
    List,
    Optional,
    Tuple,
)

# From: https://github.com/bitcoin/bitcoin/blob/master/src/script/descriptor.cpp

def PolyMod(c: int, val: int) -> int:
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
    return desc + "#" + DescriptorChecksum(desc)


class PubkeyProvider(object):
    def __init__(
        self,
        origin: Optional['KeyOriginInfo'],
        pubkey: str,
        deriv_path: Optional[str]
    ) -> None:
        self.origin = origin
        self.pubkey = pubkey
        self.deriv_path = deriv_path

    @classmethod
    def parse(cls, s: str) -> 'PubkeyProvider':
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
        s = ""
        if self.origin:
            s += "[{}]".format(self.origin.to_string())
        s += self.pubkey
        if self.deriv_path:
            s += self.deriv_path
        return s

    def __lt__(self, other: 'PubkeyProvider') -> bool:
        return self.pubkey < other.pubkey


class Descriptor(object):
    def __init__(
        self,
        pubkeys: List['PubkeyProvider'],
        subdescriptor: Optional['Descriptor'],
        name: str
    ) -> None:
        self.pubkeys = pubkeys
        self.subdescriptor = subdescriptor
        self.name = name

    def to_string_no_checksum(self) -> str:
        return "{}({}{})".format(
            self.name,
            ",".join([p.to_string() for p in self.pubkeys]),
            self.subdescriptor.to_string_no_checksum() if self.subdescriptor else ""
        )

    def to_string(self) -> str:
        return AddChecksum(self.to_string_no_checksum())


class PKHDescriptor(Descriptor):
    def __init__(
        self,
        pubkey: 'PubkeyProvider'
    ) -> None:
        super().__init__([pubkey], None, "pkh")


class WPKHDescriptor(Descriptor):
    def __init__(
        self,
        pubkey: 'PubkeyProvider'
    ) -> None:
        super().__init__([pubkey], None, "wpkh")


class MultisigDescriptor(Descriptor):
    def __init__(
        self,
        pubkeys: List['PubkeyProvider'],
        thresh: int,
        is_sorted: bool
    ) -> None:
        super().__init__(pubkeys, None, "sortedmulti" if is_sorted else "multi")
        self.thresh = thresh
        if is_sorted:
            self.pubkeys.sort()

    def to_string_no_checksum(self) -> str:
        return "{}({},{})".format(self.name, self.thresh, ",".join([p.to_string() for p in self.pubkeys]))


class SHDescriptor(Descriptor):
    def __init__(
        self,
        subdescriptor: Optional['Descriptor']
    ) -> None:
        super().__init__([], subdescriptor, "sh")


class WSHDescriptor(Descriptor):
    def __init__(
        self,
        subdescriptor: Optional['Descriptor']
    ) -> None:
        super().__init__([], subdescriptor, "wsh")


def _get_func_expr(s: str) -> Tuple[str, str]:
    """
    Get the function name and then the expression inside
    """
    start = s.index("(")
    end = s.rindex(")")
    return s[0:start], s[start + 1:end]


def parse_pubkey(expr: str) -> Tuple['PubkeyProvider', str]:
    end = len(expr)
    comma_idx = expr.find(",")
    next_expr = ""
    if comma_idx != -1:
        end = comma_idx
        next_expr = expr[end + 1:]
    return PubkeyProvider.parse(expr[:end]), next_expr


class _ParseDescriptorContext(Enum):
    TOP = 1
    P2SH = 2
    P2WSH = 3


def _parse_descriptor(desc: str, ctx: '_ParseDescriptorContext') -> 'Descriptor':
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
    i = desc.find("#")
    if i != -1:
        checksum = desc[i + 1:]
        desc = desc[:i]
        computed = DescriptorChecksum(desc)
        if computed != checksum:
            raise ValueError("The checksum does not match; Got {}, expected {}".format(checksum, computed))
    return _parse_descriptor(desc, _ParseDescriptorContext.TOP)
