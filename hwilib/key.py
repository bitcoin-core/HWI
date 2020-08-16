#!/usr/bin/env python3
# Copyright (c) 2020 The HWI developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from . import base58

import binascii
import struct
from typing import (
    Dict,
)

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
