
#
# base58.py
# Original source: git://github.com/joric/brutus.git
# which was forked from git://github.com/samrushing/caesure.git
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

from binascii import hexlify, unhexlify
import struct
from serializations import hash256, hash160

def encode(b):
    """Encode bytes to a base58-encoded string"""

    # Convert big-endian bytes to integer
    n = int('0x0' + hexlify(b).decode('utf8'), 16)

    # Divide that integer into bas58
    res = []
    while n > 0:
        n, r = divmod (n, 58)
        res.append(b58_digits[r])
    res = ''.join(res[::-1])

    # Encode leading zeros as base58 zeros
    import sys
    czero = b'\x00'
    if sys.version > '3':
        # In Python3 indexing a bytes returns numbers, not characters.
        czero = 0
    pad = 0
    for c in b:
        if c == czero: pad += 1
        else: break
    return b58_digits[0] * pad + res

def decode(s):
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''

    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise InvalidBase58Error('Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n += digit

    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]: pad += 1
        else: break
    return b'\x00' * pad + res

def get_xpub_fingerprint(s):
    data = decode(s)
    fingerprint = data[5:9]
    return struct.unpack("<I", fingerprint)[0]

def get_xpub_id(xpub):
    data = decode(xpub)
    pubkey = data[-37:-4]
    return hexlify(hash160(pubkey)[::-1]).decode()

def to_address(b, version):
    data = version + b
    checksum = hash256(data)[0:4]
    data += checksum
    return encode(data)

def xpub_to_address(xpub):
    data = decode(xpub)
    pubkey = data[-37:-4]
    pkh = hash160(pubkey)
    return to_address(pkh, b'\x6f')

def xpub_to_pub_hex(xpub):
    data = decode(xpub)
    pubkey = data[-37:-4]
    return hexlify(pubkey).decode()
