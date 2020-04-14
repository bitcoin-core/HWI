
#
# base58.py
# Original source: git://github.com/joric/brutus.git
# which was forked from git://github.com/samrushing/caesure.git
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

import hashlib
import struct
from binascii import hexlify, unhexlify
from typing import List
b58_digits: str = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def sha256(s):
    return hashlib.new('sha256', s).digest()

def hash256(s):
    return sha256(sha256(s))

def encode(b: bytes) -> str:
    """Encode bytes to a base58-encoded string"""

    # Convert big-endian bytes to integer
    n: int = int('0x0' + hexlify(b).decode('utf8'), 16)

    # Divide that integer into base58
    temp: List[str] = []
    while n > 0:
        n, r = divmod(n, 58)
        temp.append(b58_digits[r])
    res: str = ''.join(temp[::-1])

    # Encode leading zeros as base58 zeros
    czero: int = 0
    pad: int = 0
    for c in b:
        if c == czero:
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res

def decode(s: str) -> bytes:
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''

    # Convert the string to an integer
    n: int = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise ValueError('Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n += digit

    # Convert the integer to bytes
    h: str = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + res

def get_xpub_fingerprint(s: str) -> str:
    data = decode(s)
    fingerprint = data[5:9]
    return struct.unpack("<I", fingerprint)[0]

def get_xpub_fingerprint_hex(xpub: str) -> str:
    data = decode(xpub)
    fingerprint = data[5:9]
    return hexlify(fingerprint).decode()

def to_address(b: bytes, version: bytes) -> str:
    data = version + b
    checksum = hash256(data)[0:4]
    data += checksum
    return encode(data)

def xpub_to_pub_hex(xpub: str) -> str:
    data = decode(xpub)
    pubkey = data[-37:-4]
    return hexlify(pubkey).decode()

def xpub_main_2_test(xpub: str) -> str:
    data = decode(xpub)
    test_data = b'\x04\x35\x87\xCF' + data[4:-4]
    checksum = hash256(test_data)[0:4]
    return encode(test_data + checksum)
