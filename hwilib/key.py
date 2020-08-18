#!/usr/bin/env python3
# Copyright (c) 2020 The HWI developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from . import base58

import binascii
import struct
from typing import (
    Dict,
    Sequence,
)

HARDENED_FLAG = 1 << 31


def H_(x: int) -> int:
    """
    Shortcut function that "hardens" a number in a BIP44 path.
    """
    return x | HARDENED_FLAG

def is_hardened(i: int) -> bool:
    """
    Returns whether an index is hardened
    """
    return i & HARDENED_FLAG != 0


# An extended public key (xpub) or private key (xprv). Just a data container for now.
# Only handles deserialization of extended keys into component data to be handled by something else
class ExtendedKey(object):

    MAINNET_PUBLIC = b'\x04\x88\xB2\x1E'
    MAINNET_PRIVATE = b'\x04\x88\xAD\xE4'
    TESTNET_PUBLIC = b'\x04\x35\x87\xCF'
    TESTNET_PRIVATE = b'\x04\x35\x83\x94'

    def __init__(self) -> None:
        self.is_testnet: bool = False
        self.is_private: bool = False
        self.depth: int = 0
        self.parent_fingerprint: bytes = b''
        self.child_num: int = 0
        self.chaincode: bytes = b''
        self.pubkey: bytes = b''
        self.privkey: bytes = b''

    def deserialize(self, xpub: str) -> None:
        data = base58.decode(xpub)[:-4] # Decoded xpub without checksum

        version = data[0:4]
        if version == ExtendedKey.TESTNET_PUBLIC or version == ExtendedKey.TESTNET_PRIVATE:
            self.is_testnet = True
        if version == ExtendedKey.MAINNET_PRIVATE or version == ExtendedKey.TESTNET_PRIVATE:
            self.is_private = True

        self.depth = data[4]
        self.parent_fingerprint = data[5:9]
        self.child_num = struct.unpack('>I', data[9:13])[0]
        self.chaincode = data[13:45]

        if self.is_private:
            self.privkey = data[46:]
        else:
            self.pubkey = data[45:78]

    def get_printable_dict(self) -> Dict[str, object]:
        d: Dict[str, object] = {}
        d['testnet'] = self.is_testnet
        d['private'] = self.is_private
        d['depth'] = self.depth
        d['parent_fingerprint'] = binascii.hexlify(self.parent_fingerprint).decode()
        d['child_num'] = self.child_num
        d['chaincode'] = binascii.hexlify(self.chaincode).decode()
        if self.is_private:
            d['privkey'] = binascii.hexlify(self.privkey).decode()
        else:
            d['pubkey'] = binascii.hexlify(self.pubkey).decode()
        return d


class KeyOriginInfo(object):
    def __init__(self, fingerprint: bytes, path: Sequence[int]) -> None:
        self.fingerprint: bytes = fingerprint
        self.path: Sequence[int] = path

    @classmethod
    def deserialize(cls, s: bytes) -> 'KeyOriginInfo':
        """
        Deserialize a serialized KeyOriginInfo.
        They will be serialized in the same way that PSBTs serialize derivation paths
        """
        fingerprint = s[0:4]
        s = s[4:]
        path = list(struct.unpack("<" + "I" * (len(s) // 4), s))
        return cls(fingerprint, path)

    def serialize(self) -> bytes:
        """
        Serializes the KeyOriginInfo in the same way that derivation paths are stored in PSBTs
        """
        r = self.fingerprint
        r += struct.pack("<" + "I" * len(self.path), *self.path)
        return r

    def _path_string(self) -> str:
        s = ""
        for i in self.path:
            hardened = is_hardened(i)
            i &= ~HARDENED_FLAG
            s += "/" + str(i)
            if hardened:
                s += "'"
        return s

    def to_string(self) -> str:
        """
        Return the KeyOriginInfo as a string in the form <fingerprint>/<index>/<index>/...
        This is the same way that KeyOriginInfo is shown in descriptors
        """
        s = binascii.hexlify(self.fingerprint).decode()
        s += self._path_string()
        return s

    def get_derivation_path(self) -> str:
        """
        Return the string for just the path
        """
        return "m" + self._path_string()


def parse_path(nstr: str) -> Sequence[int]:
    """
    Convert BIP32 path string to list of uint32 integers with hardened flags.
    Several conventions are supported to set the hardened flag: -1, 1', 1h

    e.g.: "0/1h/1" -> [0, 0x80000001, 1]

    :param nstr: path string
    :return: list of integers
    """
    if not nstr:
        return []

    n = nstr.split("/")

    # m/a/b/c => a/b/c
    if n[0] == "m":
        n = n[1:]

    def str_to_harden(x: str) -> int:
        if x.startswith("-"):
            return H_(abs(int(x)))
        elif x.endswith(("h", "'")):
            return H_(int(x[:-1]))
        else:
            return int(x)

    try:
        return [str_to_harden(x) for x in n]
    except Exception:
        raise ValueError("Invalid BIP32 path", nstr)
