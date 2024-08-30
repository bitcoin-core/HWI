"""
Common Classes and Utilities
****************************
"""

import hashlib

from enum import Enum

from typing import Union


class Chain(Enum):
    """
    The blockchain network to use
    """
    MAIN = 0 #: Bitcoin Main network
    TEST = 1 #: Bitcoin Test network
    REGTEST = 2 #: Bitcoin Core Regression Test network
    SIGNET = 3 #: Bitcoin Signet

    def __str__(self) -> str:
        return str(self.name).lower()

    def __repr__(self) -> str:
        return str(self)

    @staticmethod
    def argparse(s: str) -> Union['Chain', str]:
        try:
            return Chain[s.upper()]
        except KeyError:
            return s


class AddressType(Enum):
    """
    The type of address to use
    """
    LEGACY = 1 #: Legacy address type. P2PKH for single sig, P2SH for scripts.
    WIT = 2 #: Native segwit v0 address type. P2WPKH for single sig, P2WSH for scripts.
    SH_WIT = 3 #: Nested segwit v0 address type. P2SH-P2WPKH for single sig, P2SH-P2WSH for scripts.
    TAP = 4 #: Segwit v1 Taproot address type. P2TR always.

    def __str__(self) -> str:
        return str(self.name).lower()

    def __repr__(self) -> str:
        return str(self)

    @staticmethod
    def argparse(s: str) -> Union['AddressType', str]:
        try:
            return AddressType[s.upper()]
        except KeyError:
            return s


def sha256(s: bytes) -> bytes:
    """
    Perform a single SHA256 hash.

    :param s: Bytes to hash
    :return: The hash
    """
    return hashlib.new('sha256', s).digest()


def ripemd160(s: bytes) -> bytes:
    """
    Perform a single RIPEMD160 hash.

    :param s: Bytes to hash
    :return: The hash
    """
    return hashlib.new('ripemd160', s).digest()


def hash256(s: bytes) -> bytes:
    """
    Perform a double SHA256 hash.
    A SHA256 is performed on the input, and then a second
    SHA256 is performed on the result of the first SHA256

    :param s: Bytes to hash
    :return: The hash
    """
    return sha256(sha256(s))


def hash160(s: bytes) -> bytes:
    """
    perform a single SHA256 hash followed by a single RIPEMD160 hash on the result of the SHA256 hash.

    :param s: Bytes to hash
    :return: The hash
    """
    return ripemd160(sha256(s))
