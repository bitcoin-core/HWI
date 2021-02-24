#!/usr/bin/env python3
# Copyright (c) 2010 ArtForz -- public domain half-a-node
# Copyright (c) 2012 Jeff Garzik
# Copyright (c) 2010-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bitcoin Object Python Serializations

Modified from the test/test_framework/mininode.py file from the
Bitcoin repository

ser_*, deser_*: functions that handle serialization/deserialization
"""

import struct

from typing import (
    List,
    Sequence,
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
