import struct
import binascii
from collections import namedtuple

def dfu_parse(fd):
    # do just a little parsing of DFU headers, to find start/length of main binary
    # - not trying to support anything but what ../stm32/Makefile will generate
    # - see external/micropython/tools/pydfu.py for details
    # - works sequentially only
    fd.seek(0)

    def consume(xfd, tname, fmt, names):
        # Parses the struct defined by `fmt` from `data`, stores the parsed fields
        # into a named tuple using `names`. Returns the named tuple.
        size = struct.calcsize(fmt)
        here = xfd.read(size)
        ty = namedtuple(tname, names.split())
        values = struct.unpack(fmt, here)
        return ty(*values)

    dfu_prefix = consume(fd, 'DFU', '<5sBIB', 'signature version size targets')

    #print('dfu: ' + repr(dfu_prefix))

    assert dfu_prefix.signature == b'DfuSe', "Not a DFU file (bad magic)"

    for _ in range(dfu_prefix.targets):

        prefix = consume(fd, 'Target', '<6sBI255s2I', 
                                   'signature altsetting named name size elements')

        #print("target%d: %r" % (idx, prefix))

        for _ in range(prefix.elements):
            # Decode target prefix
            #   <   little endian
            #   I   uint32_t    element address
            #   I   uint32_t    element size
            elem = consume(fd, 'Element', '<2I', 'addr size')

            #print("target%d: %r" % (ei, elem))

            # assume bootloader at least 32k, and targeting flash.
            assert elem.addr >= 0x8008000, "Bad address?"

            yield fd.tell()
            yield elem.size

# Adapted from https://github.com/petertodd/python-bitcoinlib/blob/master/bitcoin/base58.py
def decode_xpub(s):
    assert s[1:].startswith('pub')
    b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise ValueError('Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n += digit

    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = binascii.unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]: pad += 1
        else: break
    decoded = b'\x00' * pad + res

    # Get the pubkey and chaincode
    return decoded[-37:-4], decoded[-69:-37]

def get_pubkey_string(b):
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    x = int.from_bytes(b[1:], byteorder="big")
    y = pow((x*x*x + 7) % p, (p + 1) // 4, p)
    if (y & 1 != b[0] & 1):
        y = p - y
    return x.to_bytes(32, byteorder="big") + y.to_bytes(32, byteorder="big")


def calc_local_pincode(psbt_sha, next_local_code):
    # In HSM mode, you will need this function to generate
    # the next 6-digit code for the local user.
    #
    # - next_local_code comes from the hsm_status response
    # - psbt_sha is sha256() over the binary PSBT you will be submitting
    #
    from binascii import a2b_base64
    from hashlib import sha256
    import struct, hmac

    key = a2b_base64(next_local_code)
    assert len(key) >= 15
    assert len(psbt_sha) == 32
    digest = hmac.new(key, psbt_sha, sha256).digest()

    num = struct.unpack('>I', digest[-4:])[0] & 0x7fffffff

    return '%06d' % (num % 1000000)


# EOF
