#!/usr/bin/env python3
# Copyright (c) 2010 ArtForz -- public domain half-a-node
# Copyright (c) 2012 Jeff Garzik
# Copyright (c) 2010-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bitcoin Object Python Serializations

Modified from the test/test_framework/mininode.py file from the
Bitcoin repository

CTransaction,CTxIn, CTxOut, etc....:
    data structures that should map to corresponding structures in
    bitcoin/primitives for transactions only
ser_*, deser_*: functions that handle serialization/deserialization
"""

from .common import (
    hash256,
)
from ._script import (
    is_opreturn,
    is_p2sh,
    is_p2pkh,
    is_p2pk,
    is_witness,
    is_p2wsh,
)

import struct
import copy

from typing import (
    List,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Callable,
)
from typing_extensions import Protocol

class Readable(Protocol):
    def read(self, n: int = -1) -> bytes:
        ...

class Deserializable(Protocol):
    def deserialize(self, f: Readable) -> None:
        ...

class Serializable(Protocol):
    def serialize(self) -> bytes:
        ...


# Serialization/deserialization tools
def ser_compact_size(size: int) -> bytes:
    r = b""
    if size < 253:
        r = struct.pack("B", size)
    elif size < 0x10000:
        r = struct.pack("<BH", 253, size)
    elif size < 0x100000000:
        r = struct.pack("<BI", 254, size)
    else:
        r = struct.pack("<BQ", 255, size)
    return r

def deser_compact_size(f: Readable) -> int:
    nit: int = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit

def deser_string(f: Readable) -> bytes:
    nit = deser_compact_size(f)
    return f.read(nit)

def ser_string(s: bytes) -> bytes:
    return ser_compact_size(len(s)) + s

def deser_uint256(f: Readable) -> int:
    r = 0
    for i in range(8):
        t = struct.unpack("<I", f.read(4))[0]
        r += t << (i * 32)
    return r


def ser_uint256(u: int) -> bytes:
    rs = b""
    for _ in range(8):
        rs += struct.pack("<I", u & 0xFFFFFFFF)
        u >>= 32
    return rs


def uint256_from_str(s: bytes) -> int:
    r = 0
    t = struct.unpack("<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r

D = TypeVar("D", bound=Deserializable)

def deser_vector(f: Readable, c: Callable[[], D]) -> List[D]:
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = c()
        t.deserialize(f)
        r.append(t)
    return r


def ser_vector(v: Sequence[Serializable]) -> bytes:
    r = ser_compact_size(len(v))
    for i in v:
        r += i.serialize()
    return r


def deser_string_vector(f: Readable) -> List[bytes]:
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = deser_string(f)
        r.append(t)
    return r


def ser_string_vector(v: List[bytes]) -> bytes:
    r = ser_compact_size(len(v))
    for sv in v:
        r += ser_string(sv)
    return r

def ser_sig_der(r: bytes, s: bytes) -> bytes:
    sig = b"\x30"

    # Make r and s as short as possible
    ri = 0
    for b in r:
        if b == 0:
            ri += 1
        else:
            break
    r = r[ri:]
    si = 0
    for b in s:
        if b == 0:
            si += 1
        else:
            break
    s = s[si:]

    # Make positive of neg
    first = r[0]
    if first & (1 << 7) != 0:
        r = b"\x00" + r
    first = s[0]
    if first & (1 << 7) != 0:
        s = b"\x00" + s

    # Write total length
    total_len = len(r) + len(s) + 4
    sig += struct.pack("B", total_len)

    # write r
    sig += b"\x02"
    sig += struct.pack("B", len(r))
    sig += r

    # write s
    sig += b"\x02"
    sig += struct.pack("B", len(s))
    sig += s

    sig += b"\x01"
    return sig

def ser_sig_compact(r: bytes, s: bytes, recid: bytes) -> bytes:
    rec = struct.unpack("B", recid)[0]
    prefix = struct.pack("B", 27 + 4 + rec)

    sig = b""
    sig += prefix
    sig += r + s

    return sig

# Objects that map to bitcoind objects, which can be serialized/deserialized

MSG_WITNESS_FLAG = 1 << 30

class COutPoint(object):
    def __init__(self, hash: int = 0, n: int = 0xffffffff):
        self.hash = hash
        self.n = n

    def deserialize(self, f: Readable) -> None:
        self.hash = deser_uint256(f)
        self.n = struct.unpack("<I", f.read(4))[0]

    def serialize(self) -> bytes:
        r = b""
        r += ser_uint256(self.hash)
        r += struct.pack("<I", self.n)
        return r

    def __repr__(self) -> str:
        return "COutPoint(hash=%064x n=%i)" % (self.hash, self.n)


class CTxIn(object):
    def __init__(
        self,
        outpoint: Optional[COutPoint] = None,
        scriptSig: bytes = b"",
        nSequence: int = 0,
    ):
        if outpoint is None:
            self.prevout = COutPoint()
        else:
            self.prevout = outpoint
        self.scriptSig = scriptSig
        self.nSequence = nSequence

    def deserialize(self, f: Readable) -> None:
        self.prevout = COutPoint()
        self.prevout.deserialize(f)
        self.scriptSig = deser_string(f)
        self.nSequence = struct.unpack("<I", f.read(4))[0]

    def serialize(self) -> bytes:
        r = b""
        r += self.prevout.serialize()
        r += ser_string(self.scriptSig)
        r += struct.pack("<I", self.nSequence)
        return r

    def __repr__(self) -> str:
        return "CTxIn(prevout=%s scriptSig=%s nSequence=%i)" \
            % (repr(self.prevout), self.scriptSig.hex(),
               self.nSequence)


class CTxOut(object):
    def __init__(self, nValue: int = 0, scriptPubKey: bytes = b""):
        self.nValue = nValue
        self.scriptPubKey = scriptPubKey

    def deserialize(self, f: Readable) -> None:
        self.nValue = struct.unpack("<q", f.read(8))[0]
        self.scriptPubKey = deser_string(f)

    def serialize(self) -> bytes:
        r = b""
        r += struct.pack("<q", self.nValue)
        r += ser_string(self.scriptPubKey)
        return r

    def is_opreturn(self) -> bool:
        return is_opreturn(self.scriptPubKey)

    def is_p2sh(self) -> bool:
        return is_p2sh(self.scriptPubKey)

    def is_p2wsh(self) -> bool:
        return is_p2wsh(self.scriptPubKey)

    def is_p2pkh(self) -> bool:
        return is_p2pkh(self.scriptPubKey)

    def is_p2pk(self) -> bool:
        return is_p2pk(self.scriptPubKey)

    def is_witness(self) -> Tuple[bool, int, bytes]:
        return is_witness(self.scriptPubKey)

    def __repr__(self) -> str:
        return "CTxOut(nValue=%i.%08i scriptPubKey=%s)" \
            % (self.nValue, self.nValue, self.scriptPubKey.hex())


class CScriptWitness(object):
    def __init__(self) -> None:
        # stack is a vector of strings
        self.stack: List[bytes] = []

    def __repr__(self) -> str:
        return "CScriptWitness(%s)" % \
               (",".join([x.hex() for x in self.stack]))

    def is_null(self) -> bool:
        if self.stack:
            return False
        return True


class CTxInWitness(object):
    def __init__(self) -> None:
        self.scriptWitness = CScriptWitness()

    def deserialize(self, f: Readable) -> None:
        self.scriptWitness.stack = deser_string_vector(f)

    def serialize(self) -> bytes:
        return ser_string_vector(self.scriptWitness.stack)

    def __repr__(self) -> str:
        return repr(self.scriptWitness)

    def is_null(self) -> bool:
        return self.scriptWitness.is_null()


class CTxWitness(object):
    def __init__(self) -> None:
        self.vtxinwit: List[CTxInWitness] = []

    def deserialize(self, f: Readable) -> None:
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].deserialize(f)

    def serialize(self) -> bytes:
        r = b""
        # This is different than the usual vector serialization --
        # we omit the length of the vector, which is required to be
        # the same length as the transaction's vin vector.
        for x in self.vtxinwit:
            r += x.serialize()
        return r

    def __repr__(self) -> str:
        return "CTxWitness(%s)" % \
               (';'.join([repr(x) for x in self.vtxinwit]))

    def is_null(self) -> bool:
        for x in self.vtxinwit:
            if not x.is_null():
                return False
        return True


class CTransaction(object):
    def __init__(self, tx: Optional['CTransaction'] = None) -> None:
        if tx is None:
            self.nVersion = 1
            self.vin: List[CTxIn] = []
            self.vout: List[CTxOut] = []
            self.wit = CTxWitness()
            self.nLockTime = 0
            self.sha256: Optional[int] = None
            self.hash: Optional[str] = None
        else:
            self.nVersion = tx.nVersion
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.nLockTime = tx.nLockTime
            self.sha256 = tx.sha256
            self.hash = tx.hash
            self.wit = copy.deepcopy(tx.wit)

    def deserialize(self, f: Readable) -> None:
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        self.vin = deser_vector(f, CTxIn)
        flags = 0
        if len(self.vin) == 0:
            flags = struct.unpack("<B", f.read(1))[0]
            # Not sure why flags can't be zero, but this
            # matches the implementation in bitcoind
            if (flags != 0):
                self.vin = deser_vector(f, CTxIn)
                self.vout = deser_vector(f, CTxOut)
        else:
            self.vout = deser_vector(f, CTxOut)
        if flags != 0:
            self.wit.vtxinwit = [CTxInWitness() for i in range(len(self.vin))]
            self.wit.deserialize(f)
        self.nLockTime = struct.unpack("<I", f.read(4))[0]
        self.sha256 = None
        self.hash = None

    def serialize_without_witness(self) -> bytes:
        r = b""
        r += struct.pack("<i", self.nVersion)
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        r += struct.pack("<I", self.nLockTime)
        return r

    # Only serialize with witness when explicitly called for
    def serialize_with_witness(self) -> bytes:
        flags = 0
        if not self.wit.is_null():
            flags |= 1
        r = b""
        r += struct.pack("<i", self.nVersion)
        if flags:
            r += ser_vector([])
            r += struct.pack("<B", flags)
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        if flags & 1:
            if (len(self.wit.vtxinwit) != len(self.vin)):
                # vtxinwit must have the same length as vin
                self.wit.vtxinwit = self.wit.vtxinwit[:len(self.vin)]
                for _ in range(len(self.wit.vtxinwit), len(self.vin)):
                    self.wit.vtxinwit.append(CTxInWitness())
            r += self.wit.serialize()
        r += struct.pack("<I", self.nLockTime)
        return r

    # Regular serialization is without witness -- must explicitly
    # call serialize_with_witness to include witness data.
    def serialize(self) -> bytes:
        return self.serialize_without_witness()

    # Recalculate the txid (transaction hash without witness)
    def rehash(self) -> None:
        self.sha256 = None
        self.calc_sha256()

    # We will only cache the serialization without witness in
    # self.sha256 and self.hash -- those are expected to be the txid.
    def calc_sha256(self, with_witness: bool = False) -> Optional[int]:
        if with_witness:
            # Don't cache the result, just return it
            return uint256_from_str(hash256(self.serialize_with_witness()))

        if self.sha256 is None:
            self.sha256 = uint256_from_str(hash256(self.serialize_without_witness()))
        self.hash = hash256(self.serialize())[::-1].hex()
        return None

    def is_null(self) -> bool:
        return len(self.vin) == 0 and len(self.vout) == 0

    def __repr__(self) -> str:
        return "CTransaction(nVersion=%i vin=%s vout=%s wit=%s nLockTime=%i)" \
            % (self.nVersion, repr(self.vin), repr(self.vout), repr(self.wit), self.nLockTime)
