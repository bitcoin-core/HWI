# Derive public keys with BIP 32

# Point addition, multiplication, decompression, and compression are courtesy of sipa

import binascii
import hashlib
import hmac
import struct

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def point_add(p1, p2):
    if (p1 is None):
        return p2
    if (p2 is None):
        return p1
    if (p1[0] == p2[0] and p1[1] != p2[1]):
        return None
    if (p1 == p2):
        lam = (3 * p1[0] * p1[0] * pow(2 * p1[1], p - 2, p)) % p
    else:
        lam = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], p - 2, p)) % p
    x3 = (lam * lam - p1[0] - p2[0]) % p
    return (x3, (lam * (p1[0] - x3) - p1[1]) % p)

def point_mul(p, n):
    r = None
    for i in range(256):
        if ((n >> i) & 1):
            r = point_add(r, p)
        p = point_add(p, p)
    return r

def deserialize_point(b):
    x = int.from_bytes(b[1:], byteorder="big")
    y = pow((x*x*x + 7) % p, (p + 1) // 4, p)
    if (y & 1 != b[0] & 1):
        y = p - y
    return (x,y)

def bytes_to_point(point_bytes):
    header = point_bytes[0]
    if header == b'\x04':
        x = point_bytes = point_bytes[1:33]
        y = point_bytes = point_bytes[33:65]
        return (int(binascii.hexlify(x), 16), int(binascii.hexlify(y), 16))
    return deserialize_point(point_bytes)

def point_to_bytes(p):
    return (b'\x03' if p[1] & 1 else b'\x02') + p[0].to_bytes(32, byteorder="big")

# parent_pubkey is a DER serialized public key as a bytes object
# parent_chaincode is a 32 byte bytes object with the chaincode of the parent
# i is the index of the child being derived
def CKDpub(parent_pubkey, parent_chaincode, i):
    if i >= 2 ** 31:
        raise ValueError("Index cannot be larger than 2^31")

    # Data to HMAC.  Same as CKDpriv() for public child key.
    data = parent_pubkey + struct.pack(">L", i)

    # Get HMAC of data
    I = hmac.new(parent_chaincode, data, hashlib.sha512).digest()
    Il = I[:32]
    Ir = I[32:]

    # Construct curve point Il*G+K
    Il_int = int(binascii.hexlify(Il), 16)
    child_pubkey = point_add(point_mul(G, Il_int), bytes_to_point(parent_pubkey))

    # Construct and return a new BIP32Key
    return (point_to_bytes(child_pubkey), Ir)
