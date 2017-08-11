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

    def __repr__(self):
        return "CTxOut(nValue=%i.%08i scriptPubKey=%s)" \
            % (self.nValue // COIN, self.nValue % COIN,
               bytes_to_hex_str(self.scriptPubKey))


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
        self.hd_keypaths = {}
        self.unknown = {}

class PSBT(object):

    def __init__(self, tx = None):
        if tx:
            self.tx = tx
        else:
            self.tx = CTransaction()
        self.redeem_scripts = {}
        self.witness_scripts = {}
        self.inputs = []

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
        while True:

            # read the size of the key
            try:
                key_len = deser_compact_size(f)
            except Exception:
                break

            # Check for separator
            if key_len == 0:
                last_type = 0x03

                if separators > 0:
                    self.inputs.append(copy.copy(psbt_input))
                    psbt_input = PartiallySignedInput()

                separators += 1
                continue;


            # read key
            key = f.read(key_len)

            # First byte of key is the type
            key_type = struct.unpack("b", bytearray([key[0]]))[0]
            if key_type < last_type:
                raise IOError("Type is not sequential")
            last_type = key_type

            # read in value length
            value_len = deser_compact_size(f)

            # Do stuff based on type
            # Raw tx
            if key_type == 0x00:
                self.tx.deserialize(f)
            # redeemscript
            elif key_type == 0x01:
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
            # witness script
            elif key_type == 0x02:
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
            # non witness utxo
            elif key_type == 0x03:
                # Read in the transaction
                tx = CTransaction()
                tx.deserialize(f)
                tx.calc_sha256()

                # check that this utxo matches the input
                if self.tx.vin[separators - 1].prevout.hash != tx.sha256:
                    raise IOError("Provided non witness utxo does not match the required utxo for input")

                psbt_input.non_witness_utxo = tx
            # witness utxo
            elif key_type == 0x04:
                # read in the utxo
                vout = CTxOut()
                vout.deserialize(f)

                # add to map
                psbt_input.witness_utxo = vout
            #partial signatures
            elif key_type == 0x05:
                # read in the pubkey from key
                pubkey = key[1:]

                # read in the signature from value
                signature = f.read(value_len)

                # add to list
                psbt_input.partial_sigs[pubkey] = signature
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
                    r += b"\x01\x04"
                    utxo = psbt_input.witness_utxo.serialize()
                    r += ser_compact_size(len(utxo))
                    r += utxo
                elif psbt_input.non_witness_utxo:
                    r += b"\x01\x03"
                    utxo = psbt_input.non_witness_utxo.serialize()
                    r += ser_compact_size(len(utxo))
                    r += utxo

                # write any partial signatures
                for pubkey, sig in psbt_input.partial_sigs.items():
                    r += ser_compact_size(len(pubkey) + 1)
                    r += b"\x05"
                    r += pubkey
                    r += ser_compact_size(len(sig))
                    r += sig
            # separator
            r += b"\x00"

        # return hex string
        return binascii.hexlify(r)

if __name__ == "__main__":
    tx_str = "70736274ff01007e020000000224fd35c30ae6a3b91d4fea157b6dfe65f99222ec64d7c4cab1cea8ae7cc1c8e70000000000ffffffff24fd35c30ae6a3b91d4fea157b6dfe65f99222ec64d7c4cab1cea8ae7cc1c8e70100000000ffffffff01c0512677000000001976a914a1df2c408e2434e777604c2d7074e7cb1de365bf88ac000000001501c6602a01b964802d9ac6f87d3b82dfd2beb58b1269522102414dd7bdddd4cc5cdb0c58bbc4dbd2581b1564fec78674786fcecc2951ff5c472102bf5710e1afc286426eab28830174107d2c30cca321099f5d6c3068fe9453c58c21031f46229f46e37de9cc269acbecbe3187179e9084c6be309201a7595fb00ab01753ae1501f79cc859e9125d76d1656e40ac74256eca3a8678220020398feb11655776a3ad40e11bc3b997a6efb48fbe271df127d550be9b03afd7462102398feb11655776a3ad40e11bc3b997a6efb48fbe271df127d550be9b03afd74669522102414dd7bdddd4cc5cdb0c58bbc4dbd2581b1564fec78674786fcecc2951ff5c472102bf5710e1afc286426eab28830174107d2c30cca321099f5d6c3068fe9453c58c21031f46229f46e37de9cc269acbecbe3187179e9084c6be309201a7595fb00ab01753ae0001042000ca9a3b0000000017a914f79cc859e9125d76d1656e40ac74256eca3a867887220502bf5710e1afc286426eab28830174107d2c30cca321099f5d6c3068fe9453c58c4830450221008c38aa67ef6e4151f93b05aeedf6791df264b60c3a6fe1ba10f50062ce0d36c4022065cc7da2b189a4b1c77c275fa6206608b468c4576a04b33eb9741849c2edda3801000103fd6e010200000002271b8fddc6f282ef3eafdc73013defdf5e379fd9d257963e847d8fb66505446d000000004847304402202fe33eb56cff3711a0628b490a24d8264dd13fc2f76145855d70c90e4e32f38f02200293f5481015e8752788b4cab4b0d8a9dfc704db10fe52e701d75ae25dabb53e01feffffff98734d18111d2109552eba6fa922ee101823b99bb84b0053a028519804f6f173000000004847304402202712722c4bfb779af938e858c3bd9fd458fadbca57e2db2f9b2d507f6f6167d0022023303d9c4549015cacaa433af71a8651758a94e05e7e1cf3af5abb269c3351d801feffffff0400ca9a3b0000000017a914f79cc859e9125d76d1656e40ac74256eca3a86788700ca9a3b0000000017a914c6602a01b964802d9ac6f87d3b82dfd2beb58b128700ca9a3b0000000017a9148e12ff153070c91ebb92030b5db684ea6017f1dc87c0fab32c000000001976a914e421ff5ba6f10ccad2c83a32af9a0e0f89c34eaa88ac00000000220502bf5710e1afc286426eab28830174107d2c30cca321099f5d6c3068fe9453c58c483045022100b4ad551e8703bf548c734b2dd374220a6217a160132ea2e2783bdc151ce89e8a02206db6fe0ea6f9e77f218a98dd6f03b4470bf9e6f1b563a66ede7b83efc40b31590100"
    tx = PSBT()
    tx.deserialize(tx_str)
    serialized = tx.serialize()
    print(binascii.hexlify(binascii.unhexlify(tx_str)) == serialized)
    print(binascii.hexlify(binascii.unhexlify(tx_str)))
    print(serialized)
