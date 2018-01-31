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

from io import BytesIO, BufferedReader
from codecs import encode
import struct
import binascii
import hashlib
import copy

def sha256(s):
    return hashlib.new('sha256', s).digest()

def ripemd160(s):
    return hashlib.new('ripemd160', s).digest()

def hash256(s):
    return sha256(sha256(s))

def hash160(s):
    return ripemd160(sha256(s))


# Serialization/deserialization tools
def ser_compact_size(l):
    r = b""
    if l < 253:
        r = struct.pack("B", l)
    elif l < 0x10000:
        r = struct.pack("<BH", 253, l)
    elif l < 0x100000000:
        r = struct.pack("<BI", 254, l)
    else:
        r = struct.pack("<BQ", 255, l)
    return r

def deser_compact_size(f):
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit

def deser_string(f):
    nit = deser_compact_size(f)
    return f.read(nit)

def ser_string(s):
    return ser_compact_size(len(s)) + s

def deser_uint256(f):
    r = 0
    for i in range(8):
        t = struct.unpack("<I", f.read(4))[0]
        r += t << (i * 32)
    return r


def ser_uint256(u):
    rs = b""
    for i in range(8):
        rs += struct.pack("<I", u & 0xFFFFFFFF)
        u >>= 32
    return rs


def uint256_from_str(s):
    r = 0
    t = struct.unpack("<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r


def uint256_from_compact(c):
    nbytes = (c >> 24) & 0xFF
    v = (c & 0xFFFFFF) << (8 * (nbytes - 3))
    return v


def deser_vector(f, c):
    nit = deser_compact_size(f)
    r = []
    for i in range(nit):
        t = c()
        t.deserialize(f)
        r.append(t)
    return r


# ser_function_name: Allow for an alternate serialization function on the
# entries in the vector (we use this for serializing the vector of transactions
# for a witness block).
def ser_vector(l, ser_function_name=None):
    r = ser_compact_size(len(l))
    for i in l:
        if ser_function_name:
            r += getattr(i, ser_function_name)()
        else:
            r += i.serialize()
    return r


def deser_uint256_vector(f):
    nit = deser_compact_size(f)
    r = []
    for i in range(nit):
        t = deser_uint256(f)
        r.append(t)
    return r


def ser_uint256_vector(l):
    r = ser_compact_size(len(l))
    for i in l:
        r += ser_uint256(i)
    return r


def deser_string_vector(f):
    nit = deser_compact_size(f)
    r = []
    for i in range(nit):
        t = deser_string(f)
        r.append(t)
    return r


def ser_string_vector(l):
    r = ser_compact_size(len(l))
    for sv in l:
        r += ser_string(sv)
    return r


def deser_int_vector(f):
    nit = deser_compact_size(f)
    r = []
    for i in range(nit):
        t = struct.unpack("<i", f.read(4))[0]
        r.append(t)
    return r


def ser_int_vector(l):
    r = ser_compact_size(len(l))
    for i in l:
        r += struct.pack("<i", i)
    return r

# Deserialize from a hex string representation (eg from RPC)
def FromHex(obj, hex_string):
    obj.deserialize(BytesIO(hex_str_to_bytes(hex_string)))
    return obj

# Convert a binary-serializable object to hex (eg for submission via RPC)
def ToHex(obj):
    return bytes_to_hex_str(obj.serialize())

def ser_sig_der(r, s):
    sig = b"\x30"

    # Make r and s as short as possible
    ri = 0
    for b in r:
        if b == "\x00":
            ri += 1
        else:
            break
    r = r[ri:]
    si = 0
    for b in s:
        if b == "\x00":
            si += 1
        else:
            break;
    s = s[si:]

    # Make positive of neg
    first = struct.unpack("B", r[0])[0]
    if first & (1 << 7) != 0:
        r = b"\x00" + r
    first = struct.unpack("B", s[0])[0]
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

    sig += "\x01"
    return sig

def ser_sig_compact(r, s, recid):
    rec = struct.unpack("B", recid)[0]
    prefix = struct.pack("B", 27 + 4 +rec)

    sig = b""
    sig += prefix
    sig += r + s

    return sig

# Objects that map to bitcoind objects, which can be serialized/deserialized

MSG_WITNESS_FLAG = 1<<30

class COutPoint(object):
    def __init__(self, hash=0, n=0):
        self.hash = hash
        self.n = n

    def deserialize(self, f):
        self.hash = deser_uint256(f)
        self.n = struct.unpack("<I", f.read(4))[0]

    def serialize(self):
        r = b""
        r += ser_uint256(self.hash)
        r += struct.pack("<I", self.n)
        return r

    def __repr__(self):
        return "COutPoint(hash=%064x n=%i)" % (self.hash, self.n)


class CTxIn(object):
    def __init__(self, outpoint=None, scriptSig=b"", nSequence=0):
        if outpoint is None:
            self.prevout = COutPoint()
        else:
            self.prevout = outpoint
        self.scriptSig = scriptSig
        self.nSequence = nSequence

    def deserialize(self, f):
        self.prevout = COutPoint()
        self.prevout.deserialize(f)
        self.scriptSig = deser_string(f)
        self.nSequence = struct.unpack("<I", f.read(4))[0]

    def serialize(self):
        r = b""
        r += self.prevout.serialize()
        r += ser_string(self.scriptSig)
        r += struct.pack("<I", self.nSequence)
        return r

    def __repr__(self):
        return "CTxIn(prevout=%s scriptSig=%s nSequence=%i)" \
            % (repr(self.prevout), bytes_to_hex_str(self.scriptSig),
               self.nSequence)


class CTxOut(object):
    def __init__(self, nValue=0, scriptPubKey=b""):
        self.nValue = nValue
        self.scriptPubKey = scriptPubKey

    def deserialize(self, f):
        self.nValue = struct.unpack("<q", f.read(8))[0]
        self.scriptPubKey = deser_string(f)

    def serialize(self):
        r = b""
        r += struct.pack("<q", self.nValue)
        r += ser_string(self.scriptPubKey)
        return r

    def is_p2sh(self):
        return len(self.scriptPubKey) == 23 and self.scriptPubKey[0] == b"\xa9" and self.scriptPubKey[1] == b"\x14" and self.scriptPubKey[22] == "\x87"

    def is_p2pkh(self):
        return len(self.scriptPubKey) == 25 and self.scriptPubKey[0] == b"\x76" and self.scriptPubKey[1] == b"\xa9" and self.scriptPubKey[2] == b"\x14" and self.scriptPubKey[23] == b"\x88" and self.scriptPubKey[24] == b"\xac"
    def is_p2pk(self):
        return (len(self.scriptPubKey) == 35 or len(self.scriptPubKey) == 67) and (self.scriptPubKey[0] == b"\x21" or self.scriptPubKey[0] == b"\x41") and self.scriptPubKey[-1] == b"\xac"

    def __repr__(self):
        return "CTxOut(nValue=%i.%08i scriptPubKey=%s)" \
            % (self.nValue, self.nValue, binascii.hexlify(self.scriptPubKey))


class CScriptWitness(object):
    def __init__(self):
        # stack is a vector of strings
        self.stack = []

    def __repr__(self):
        return "CScriptWitness(%s)" % \
               (",".join([bytes_to_hex_str(x) for x in self.stack]))

    def is_null(self):
        if self.stack:
            return False
        return True


class CTxInWitness(object):
    def __init__(self):
        self.scriptWitness = CScriptWitness()

    def deserialize(self, f):
        self.scriptWitness.stack = deser_string_vector(f)

    def serialize(self):
        return ser_string_vector(self.scriptWitness.stack)

    def __repr__(self):
        return repr(self.scriptWitness)

    def is_null(self):
        return self.scriptWitness.is_null()


class CTxWitness(object):
    def __init__(self):
        self.vtxinwit = []

    def deserialize(self, f):
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].deserialize(f)

    def serialize(self):
        r = b""
        # This is different than the usual vector serialization --
        # we omit the length of the vector, which is required to be
        # the same length as the transaction's vin vector.
        for x in self.vtxinwit:
            r += x.serialize()
        return r

    def __repr__(self):
        return "CTxWitness(%s)" % \
               (';'.join([repr(x) for x in self.vtxinwit]))

    def is_null(self):
        for x in self.vtxinwit:
            if not x.is_null():
                return False
        return True


class CTransaction(object):
    def __init__(self, tx=None):
        if tx is None:
            self.nVersion = 1
            self.vin = []
            self.vout = []
            self.wit = CTxWitness()
            self.nLockTime = 0
            self.sha256 = None
            self.hash = None
        else:
            self.nVersion = tx.nVersion
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.nLockTime = tx.nLockTime
            self.sha256 = tx.sha256
            self.hash = tx.hash
            self.wit = copy.deepcopy(tx.wit)

    def deserialize(self, f):
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

    def serialize_without_witness(self):
        r = b""
        r += struct.pack("<i", self.nVersion)
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        r += struct.pack("<I", self.nLockTime)
        return r

    # Only serialize with witness when explicitly called for
    def serialize_with_witness(self):
        flags = 0
        if not self.wit.is_null():
            flags |= 1
        r = b""
        r += struct.pack("<i", self.nVersion)
        if flags:
            dummy = []
            r += ser_vector(dummy)
            r += struct.pack("<B", flags)
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        if flags & 1:
            if (len(self.wit.vtxinwit) != len(self.vin)):
                # vtxinwit must have the same length as vin
                self.wit.vtxinwit = self.wit.vtxinwit[:len(self.vin)]
                for i in range(len(self.wit.vtxinwit), len(self.vin)):
                    self.wit.vtxinwit.append(CTxInWitness())
            r += self.wit.serialize()
        r += struct.pack("<I", self.nLockTime)
        return r

    # Regular serialization is without witness -- must explicitly
    # call serialize_with_witness to include witness data.
    def serialize(self):
        return self.serialize_without_witness()

    # Recalculate the txid (transaction hash without witness)
    def rehash(self):
        self.sha256 = None
        self.calc_sha256()

    # We will only cache the serialization without witness in
    # self.sha256 and self.hash -- those are expected to be the txid.
    def calc_sha256(self, with_witness=False):
        if with_witness:
            # Don't cache the result, just return it
            return uint256_from_str(hash256(self.serialize_with_witness()))

        if self.sha256 is None:
            self.sha256 = uint256_from_str(hash256(self.serialize_without_witness()))
        self.hash = encode(hash256(self.serialize())[::-1], 'hex_codec').decode('ascii')

    def is_valid(self):
        self.calc_sha256()
        for tout in self.vout:
            if tout.nValue < 0 or tout.nValue > 21000000 * COIN:
                return False
        return True

    def __repr__(self):
        return "CTransaction(nVersion=%i vin=%s vout=%s wit=%s nLockTime=%i)" \
            % (self.nVersion, repr(self.vin), repr(self.vout), repr(self.wit), self.nLockTime)

class PartiallySignedInput:
    def __init__(self):
        self.non_witness_utxo = None
        self.witness_utxo = None
        self.partial_sigs = {}
        self.unknown = {}
    def set_null(self):
        self.non_witness_utxo = None
        self.witness_utxo = None
        self.partial_sigs.clear()
        self.unknown.clear()

class PSBT(object):

    def __init__(self, tx = None):
        if tx:
            self.tx = tx
        else:
            self.tx = CTransaction()
        self.redeem_scripts = {}
        self.witness_scripts = {}
        self.inputs = []
        self.hd_keypaths = {}

    def deserialize(self, hexstring):
        f = BufferedReader(BytesIO(binascii.unhexlify(hexstring)))

        # Read the magic bytes
        magic = f.read(4)
        magic_sep = f.read(1)
        if magic != b"psbt" and magic_sep != b"\xff":
            raise IOError("invalid magic")

        last_type = 0x00

        # Read loop
        separators = 0
        psbt_input = PartiallySignedInput()
        in_globals = True
        while True:

            # read the size of the key
            try:
                key_len = deser_compact_size(f)
            except Exception:
                break

            # Check for separator
            if key_len == 0:
                in_globals = False

                if separators > 0:
                    self.inputs.append(copy.copy(psbt_input))
                    psbt_input = PartiallySignedInput()

                separators += 1
                continue;


            # read key
            key = f.read(key_len)

            # First byte of key is the type
            key_type = struct.unpack("b", bytearray([key[0]]))[0]

            # read in value length
            value_len = deser_compact_size(f)

            # Do stuff based on type
            if key_type == 0x00:
                # Raw tx
                if in_globals:
                    self.tx.deserialize(f)
                # Non-witness utxo
                else:
                    # Read in the transaction
                    tx = CTransaction()
                    tx.deserialize(f)
                    tx.calc_sha256()

                    # check that this utxo matches the input
                    if self.tx.vin[separators - 1].prevout.hash != tx.sha256:
                        raise IOError("Provided non witness utxo does not match the required utxo for input")

                    psbt_input.non_witness_utxo = tx
            elif key_type == 0x01:
                # redeemscript
                if in_globals:
                    # retrieve hash160 from key
                    script_hash160 = key[1:]

                    # read in the redeemscript
                    redeemscript = f.read(value_len)

                    # Check redeemscript and its hash
                    real_hash160 = hash160(redeemscript)
                    if script_hash160 != real_hash160:
                        raise IOError("Provided hash160 does not match the redeemscript's hash160")

                    # add to map
                    self.redeem_scripts[script_hash160] = redeemscript
                # witness utxo
                else:
                    # read in the utxo
                    vout = CTxOut()
                    vout.deserialize(f)

                    # add to map
                    psbt_input.witness_utxo = vout
            elif key_type == 0x02:
                # witness script
                if in_globals:
                    # retrieve sha256 from key
                    script_sha256 = key[1:]

                    # read in the witness script
                    witnessscript = f.read(value_len)

                    # check witnessscript and its hash
                    real_sha256 = sha256(witnessscript)
                    if script_sha256 != real_sha256:
                        raise IOError("Provided sha256 does not match the witnessscript's sha256")

                    # add to map
                    self.witness_scripts[script_sha256] = witnessscript
                # partial signature
                else:
                    # read in the pubkey from key
                    pubkey = key[1:]

                    # read in the signature from value
                    signature = f.read(value_len)

                    # add to list
                    psbt_input.partial_sigs[pubkey] = signature
            # hd key paths
            elif key_type == 0x03:
                # read in pubkey from key
                pubkey = key[1:]

                # read in array of integers from value
                value = f.read(value_len)
                keypath = []
                i = 0
                while i < value_len:
                    keypath.append(struct.unpack("<I", value[i:i + 4])[0])
                    i += 4

                # add to keypath map
                self.hd_keypaths[pubkey] = keypath

            # unknown stuff
            else:
                # read in the value
                val = f.read(value_len)

                # global data
                if separators == 0:
                    unknown[key] = val
                else:
                    psbt_input.unknown[key] = val

    def serialize(self):
        r = b""

        # magic bytes
        r += b"\x70\x73\x62\x74\xff"

        # unsigned tx flag
        r += b"\x01\x00"

        # write serialized tx
        tx = self.tx.serialize_with_witness()
        r += ser_compact_size(len(tx))
        r += tx

        # write redem scripts and witness scripts
        for script_hash, script in self.redeem_scripts.items():
            r += ser_compact_size(len(script_hash) + 1)
            r += b"\x01"
            r += script_hash
            r += ser_compact_size(len(script))
            r += script
        for script_hash, script in self.witness_scripts.items():
            r += ser_compact_size(len(script_hash) + 1)
            r += b"\x02"
            r += script_hash
            r += ser_compact_size(len(script))
            r += script

        # write hd keypaths
        for fingerprint, keypath in self.hd_keypaths.items():
            r += ser_compact_size(len(fingerprint) + 1)
            r += b"\x03"
            r += fingerprint
            r += ser_compact_size(len(keypath) * 4)
            for num in keypath:
                r += struct.pack("<I", num)

        # separator
        r += b"\x00"

        # inputs
        for i in range(len(self.tx.vin)):
            tx_in = self.tx.vin[i]
            psbt_input = self.inputs[i]
            try:
                tx_in_wit = self.tx.wit.vtxinwit[i]
            except:
                tx_in_wit = None
            if not tx_in.scriptSig and not tx_in_wit:
                # If there is a witness utxo, then don't add the non witness one
                if psbt_input.witness_utxo:
                    r += b"\x01\x01"
                    utxo = psbt_input.witness_utxo.serialize()
                    r += ser_compact_size(len(utxo))
                    r += utxo
                elif psbt_input.non_witness_utxo:
                    r += b"\x01\x00"
                    utxo = psbt_input.non_witness_utxo.serialize()
                    r += ser_compact_size(len(utxo))
                    r += utxo

                # write any partial signatures
                for pubkey, sig in psbt_input.partial_sigs.items():
                    r += ser_compact_size(len(pubkey) + 1)
                    r += b"\x02"
                    r += pubkey
                    r += ser_compact_size(len(sig))
                    r += sig

            # separator
            r += b"\x00"

        # return hex string
        return binascii.hexlify(r)

if __name__ == "__main__":
    tx_str = "70736274ff01007e020000000269309231ff7253ee0358fa1bf6f87832adaf289e90c9a6c751ca984dc6f5e9bf0000000000ffffffff69309231ff7253ee0358fa1bf6f87832adaf289e90c9a6c751ca984dc6f5e9bf0100000000ffffffff01c0512677000000001976a9148a172cef76ea0dbb32906f4bdb16ca71d7120c4e88ac000000001501b891e2c295362be87b7ec33f7eb49d368e4414bf695221021a0f39420f3c09bacf273a8d70a57f65994367e2e3fef0aea3e5062b68eae24d2103c3c411ed379c0c723032eb4290c11a4eb129301ffe4f7d9452b3828bacd8ab5221029340aa786b2f617717b33a1fc065f1ac627419390e51b81e14b675142b38697353ae1501f71c5b393c1dac613b171fae28d43f1d56dcb5e62200204c55a98cf8bcfcc5d7ce58b47f38d051d9ad93bf93689ee8f4010b4cb9be907d21024c55a98cf8bcfcc5d7ce58b47f38d051d9ad93bf93689ee8f4010b4cb9be907d695221021a0f39420f3c09bacf273a8d70a57f65994367e2e3fef0aea3e5062b68eae24d2103c3c411ed379c0c723032eb4290c11a4eb129301ffe4f7d9452b3828bacd8ab5221029340aa786b2f617717b33a1fc065f1ac627419390e51b81e14b675142b38697353ae0001012000ca9a3b0000000017a914f71c5b393c1dac613b171fae28d43f1d56dcb5e687220203c3c411ed379c0c723032eb4290c11a4eb129301ffe4f7d9452b3828bacd8ab524730440220118786d0c8be84990a7b91bf3e5785f76c21ec0af95e1ff4e6188e889feb0c5902205f6aedb27efe700f22016480485fe702528ba52c8fef04b7def4b609652f8b7601000100fd6e0102000000020072fa62c337b714b84d54f4cc06c6c6ea77c27bee1715a07ca95f9bdd1cd84f000000004847304402207b6d2a7f9f092fca96e351b8ee1443adef3d7480c90b9098e5b1b6ad3acfdf9802207149d6289cebb49c24f5d8107f01dfb431bbf574d73988497c1de84db0c9427401fefffffff313a21a58d6c2d3dabe2254aa5236a5c923dd1b1d849bac4d44f6783aa5885400000000484730440220570710941112b315b768d5468e167895c8d4a6e123980c819619f68c5213da5e0220703d08524331733c628e96872268493ecb6be97ccae555d381a040c526df186301feffffff0400ca9a3b0000000017a914f71c5b393c1dac613b171fae28d43f1d56dcb5e68700ca9a3b0000000017a914b891e2c295362be87b7ec33f7eb49d368e4414bf8700ca9a3b0000000017a91425b43bde0b3d4adb6b2560c8ed6e34fae073f46b87c0fab32c000000001976a914666494defa0621b18222c9463ce3e696216b177d88ac00000000220203c3c411ed379c0c723032eb4290c11a4eb129301ffe4f7d9452b3828bacd8ab52473044022016f36b657af3cf1f583125bf110793672902d38f10bfb14479697340222453e9022075e9ac9a759f4d3e3e1cb0402e32277fafb66ed4d758d504acaa6d1f2175b9e00100"
    tx = PSBT()
    tx.deserialize(tx_str)
    serialized = tx.serialize()
    print(binascii.hexlify(binascii.unhexlify(tx_str)) == serialized)
    print(binascii.hexlify(binascii.unhexlify(tx_str)))
    print(serialized)
