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

import base64
import binascii
import copy
import hashlib
import struct
from codecs import encode
from io import BufferedReader, BytesIO

from . import base58
from .errors import PSBTSerializationError


def sha256(s):
    return hashlib.new("sha256", s).digest()


def ripemd160(s):
    return hashlib.new("ripemd160", s).digest()


def hash256(s):
    return sha256(sha256(s))


def hash160(s):
    return ripemd160(sha256(s))


# Serialization/deserialization tools
def ser_compact_size(size):
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
    for _ in range(8):
        rs += struct.pack("<I", u & 0xFFFFFFFF)
        u >>= 32
    return rs


def uint256_from_str(s):
    r = 0
    t = struct.unpack("<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r


def deser_vector(f, c):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = c()
        t.deserialize(f)
        r.append(t)
    return r


# ser_function_name: Allow for an alternate serialization function on the
# entries in the vector (we use this for serializing the vector of transactions
# for a witness block).
def ser_vector(v, ser_function_name=None):
    r = ser_compact_size(len(v))
    for i in v:
        if ser_function_name:
            r += getattr(i, ser_function_name)()
        else:
            r += i.serialize()
    return r


def deser_string_vector(f):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = deser_string(f)
        r.append(t)
    return r


def ser_string_vector(v):
    r = ser_compact_size(len(v))
    for sv in v:
        r += ser_string(sv)
    return r


def Base64ToHex(s):
    return binascii.hexlify(base64.b64decode(s))


def HexToBase64(s):
    return base64.b64encode(binascii.unhexlify(s))


def ser_sig_der(r, s):
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


def ser_sig_compact(r, s, recid):
    rec = struct.unpack("B", recid)[0]
    prefix = struct.pack("B", 27 + 4 + rec)

    sig = b""
    sig += prefix
    sig += r + s

    return sig


# Objects that map to bitcoind objects, which can be serialized/deserialized

MSG_WITNESS_FLAG = 1 << 30


class COutPoint(object):
    def __init__(self, hash=0, n=0xFFFFFFFF):
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
        return "CTxIn(prevout=%s scriptSig=%s nSequence=%i)" % (
            repr(self.prevout),
            self.scriptSig.hex(),
            self.nSequence,
        )


def is_p2sh(script):
    return (
        len(script) == 23
        and script[0] == 0xA9
        and script[1] == 0x14
        and script[22] == 0x87
    )


def is_p2pkh(script):
    return (
        len(script) == 25
        and script[0] == 0x76
        and script[1] == 0xA9
        and script[2] == 0x14
        and script[23] == 0x88
        and script[24] == 0xAC
    )


def is_p2pk(script):
    return (
        (len(script) == 35 or len(script) == 67)
        and (script[0] == 0x21 or script[0] == 0x41)
        and script[-1] == 0xAC
    )


def is_witness(script):
    if len(script) < 4 or len(script) > 42:
        return (False, None, None)

    if script[0] != 0 and (script[0] < 81 or script[0] > 96):
        return (False, None, None)

    if script[1] + 2 == len(script):
        return (True, script[0] - 0x50 if script[0] else 0, script[2:])


def is_p2wpkh(script):
    is_wit, wit_ver, wit_prog = is_witness(script)
    if not is_wit:
        return False
    elif wit_ver != 0:
        return False
    return len(wit_prog) == 20


def is_p2wsh(script):
    is_wit, wit_ver, wit_prog = is_witness(script)
    if not is_wit:
        return False
    elif wit_ver != 0:
        return False
    return len(wit_prog) == 32


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
        return is_p2sh(self.scriptPubKey)

    def is_p2pkh(self):
        return is_p2pkh(self.scriptPubKey)

    def is_p2pk(self):
        return is_p2pk(self.scriptPubKey)

    def is_witness(self):
        return is_witness(self.scriptPubKey)

    def __repr__(self):
        return "CTxOut(nValue=%i.%08i scriptPubKey=%s)" % (
            self.nValue,
            self.nValue,
            binascii.hexlify(self.scriptPubKey),
        )


class CScriptWitness(object):
    def __init__(self):
        # stack is a vector of strings
        self.stack = []

    def __repr__(self):
        return "CScriptWitness(%s)" % (",".join([x.hex() for x in self.stack]))

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
        return "CTxWitness(%s)" % (";".join([repr(x) for x in self.vtxinwit]))

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
            if flags != 0:
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
            if len(self.wit.vtxinwit) != len(self.vin):
                # vtxinwit must have the same length as vin
                self.wit.vtxinwit = self.wit.vtxinwit[: len(self.vin)]
                for _ in range(len(self.wit.vtxinwit), len(self.vin)):
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
        self.hash = encode(hash256(self.serialize())[::-1], "hex_codec").decode("ascii")

    def is_null(self):
        return len(self.vin) == 0 and len(self.vout) == 0

    def __repr__(self):
        return "CTransaction(nVersion=%i vin=%s vout=%s wit=%s nLockTime=%i)" % (
            self.nVersion,
            repr(self.vin),
            repr(self.vout),
            repr(self.wit),
            self.nLockTime,
        )


def DeserializeHDKeypath(f, key, hd_keypaths):
    if len(key) != 34 and len(key) != 66:
        raise PSBTSerializationError(
            "Size of key was not the expected size for the type partial signature pubkey"
        )
    pubkey = key[1:]
    if pubkey in hd_keypaths:
        raise PSBTSerializationError(
            "Duplicate key, input partial signature for pubkey already provided"
        )

    value = deser_string(f)
    hd_keypaths[pubkey] = struct.unpack("<" + "I" * (len(value) // 4), value)


def SerializeHDKeypath(hd_keypaths, type):
    r = b""
    for pubkey, path in sorted(hd_keypaths.items()):
        r += ser_string(type + pubkey)
        packed = struct.pack("<" + "I" * len(path), *path)
        r += ser_string(packed)
    return r


class PartiallySignedInput:
    def __init__(self):
        self.non_witness_utxo = None
        self.witness_utxo = None
        self.partial_sigs = {}
        self.sighash = 0
        self.redeem_script = b""
        self.witness_script = b""
        self.hd_keypaths = {}
        self.final_script_sig = b""
        self.final_script_witness = CTxInWitness()
        self.unknown = {}

    def set_null(self):
        self.non_witness_utxo = None
        self.witness_utxo = None
        self.partial_sigs.clear()
        self.sighash = 0
        self.redeem_script = b""
        self.witness_script = b""
        self.hd_keypaths.clear()
        self.final_script_sig = b""
        self.final_script_witness = CTxInWitness()
        self.unknown.clear()

    def deserialize(self, f):
        while True:
            # read the key
            try:
                key = deser_string(f)
            except Exception:
                break

            # Check for separator
            if len(key) == 0:
                break

            # First byte of key is the type
            key_type = struct.unpack("b", bytearray([key[0]]))[0]

            if key_type == 0:
                if self.non_witness_utxo:
                    raise PSBTSerializationError(
                        "Duplicate Key, input non witness utxo already provided"
                    )
                elif len(key) != 1:
                    raise PSBTSerializationError(
                        "non witness utxo key is more than one byte type"
                    )
                self.non_witness_utxo = CTransaction()
                value = BufferedReader(BytesIO(deser_string(f)))
                self.non_witness_utxo.deserialize(value)
                self.non_witness_utxo.rehash()

            elif key_type == 1:
                if self.witness_utxo:
                    raise PSBTSerializationError(
                        "Duplicate Key, input witness utxo already provided"
                    )
                elif len(key) != 1:
                    raise PSBTSerializationError(
                        "witness utxo key is more than one byte type"
                    )
                self.witness_utxo = CTxOut()
                value = BufferedReader(BytesIO(deser_string(f)))
                self.witness_utxo.deserialize(value)

            elif key_type == 2:
                if len(key) != 34 and len(key) != 66:
                    raise PSBTSerializationError(
                        "Size of key was not the expected size for the type partial signature pubkey"
                    )
                pubkey = key[1:]
                if pubkey in self.partial_sigs:
                    raise PSBTSerializationError(
                        "Duplicate key, input partial signature for pubkey already provided"
                    )

                sig = deser_string(f)
                self.partial_sigs[pubkey] = sig

            elif key_type == 3:
                if self.sighash > 0:
                    raise PSBTSerializationError(
                        "Duplicate key, input sighash type already provided"
                    )
                elif len(key) != 1:
                    raise PSBTSerializationError(
                        "sighash key is more than one byte type"
                    )
                value = deser_string(f)
                self.sighash = struct.unpack("<I", value)[0]

            elif key_type == 4:
                if len(self.redeem_script) != 0:
                    raise PSBTSerializationError(
                        "Duplicate key, input redeemScript already provided"
                    )
                elif len(key) != 1:
                    raise PSBTSerializationError(
                        "redeemScript key is more than one byte type"
                    )
                self.redeem_script = deser_string(f)

            elif key_type == 5:
                if len(self.witness_script) != 0:
                    raise PSBTSerializationError(
                        "Duplicate key, input witnessScript already provided"
                    )
                elif len(key) != 1:
                    raise PSBTSerializationError(
                        "witnessScript key is more than one byte type"
                    )
                self.witness_script = deser_string(f)

            elif key_type == 6:
                DeserializeHDKeypath(f, key, self.hd_keypaths)

            elif key_type == 7:
                if len(self.final_script_sig) != 0:
                    raise PSBTSerializationError(
                        "Duplicate key, input final scriptSig already provided"
                    )
                elif len(key) != 1:
                    raise PSBTSerializationError(
                        "final scriptSig key is more than one byte type"
                    )
                self.final_script_sig = deser_string(f)

            elif key_type == 8:
                if not self.final_script_witness.is_null():
                    raise PSBTSerializationError(
                        "Duplicate key, input final scriptWitness already provided"
                    )
                elif len(key) != 1:
                    raise PSBTSerializationError(
                        "final scriptWitness key is more than one byte type"
                    )
                value = BufferedReader(BytesIO(deser_string(f)))
                self.final_script_witness.deserialize(value)

            else:
                if key in self.unknown:
                    raise PSBTSerializationError(
                        "Duplicate key, key for unknown value already provided"
                    )
                value = deser_string(f)
                self.unknown[key] = value

    def serialize(self):
        r = b""

        if self.non_witness_utxo:
            r += ser_string(b"\x00")
            tx = self.non_witness_utxo.serialize_with_witness()
            r += ser_string(tx)

        if self.witness_utxo:
            r += ser_string(b"\x01")
            tx = self.witness_utxo.serialize()
            r += ser_string(tx)

        if len(self.final_script_sig) == 0 and self.final_script_witness.is_null():
            for pubkey, sig in sorted(self.partial_sigs.items()):
                r += ser_string(b"\x02" + pubkey)
                r += ser_string(sig)

            if self.sighash > 0:
                r += ser_string(b"\x03")
                r += ser_string(struct.pack("<I", self.sighash))

            if len(self.redeem_script) != 0:
                r += ser_string(b"\x04")
                r += ser_string(self.redeem_script)

            if len(self.witness_script) != 0:
                r += ser_string(b"\x05")
                r += ser_string(self.witness_script)

            r += SerializeHDKeypath(self.hd_keypaths, b"\x06")

        if len(self.final_script_sig) != 0:
            r += ser_string(b"\x07")
            r += ser_string(self.final_script_sig)

        if not self.final_script_witness.is_null():
            r += ser_string(b"\x08")
            witstack = self.final_script_witness.serialize()
            r += ser_string(witstack)

        for key, value in sorted(self.unknown.items()):
            r += ser_string(key)
            r += ser_string(value)

        r += b"\x00"

        return r


class PartiallySignedOutput:
    def __init__(self):
        self.redeem_script = b""
        self.witness_script = b""
        self.hd_keypaths = {}
        self.unknown = {}

    def set_null(self):
        self.redeem_script = b""
        self.witness_script = b""
        self.hd_keypaths.clear()
        self.unknown.clear()

    def deserialize(self, f):
        while True:
            # read the key
            try:
                key = deser_string(f)
            except Exception:
                break

            # Check for separator
            if len(key) == 0:
                break

            # First byte of key is the type
            key_type = struct.unpack("b", bytearray([key[0]]))[0]

            if key_type == 0:
                if len(self.redeem_script) != 0:
                    raise PSBTSerializationError(
                        "Duplicate key, output redeemScript already provided"
                    )
                elif len(key) != 1:
                    raise PSBTSerializationError(
                        "Output redeemScript key is more than one byte type"
                    )
                self.redeem_script = deser_string(f)

            elif key_type == 1:
                if len(self.witness_script) != 0:
                    raise PSBTSerializationError(
                        "Duplicate key, output witnessScript already provided"
                    )
                elif len(key) != 1:
                    raise PSBTSerializationError(
                        "Output witnessScript key is more than one byte type"
                    )
                self.witness_script = deser_string(f)

            elif key_type == 2:
                DeserializeHDKeypath(f, key, self.hd_keypaths)

            else:
                if key in self.unknown:
                    raise PSBTSerializationError(
                        "Duplicate key, key for unknown value already provided"
                    )
                value = deser_string(f)
                self.unknown[key] = value

    def serialize(self):
        r = b""
        if len(self.redeem_script) != 0:
            r += ser_string(b"\x00")
            r += ser_string(self.redeem_script)

        if len(self.witness_script) != 0:
            r += ser_string(b"\x01")
            r += ser_string(self.witness_script)

        r += SerializeHDKeypath(self.hd_keypaths, b"\x02")

        for key, value in sorted(self.unknown.items()):
            r += ser_string(key)
            r += ser_string(value)

        r += b"\x00"

        return r


class PSBT(object):
    def __init__(self, tx=None):
        if tx:
            self.tx = tx
        else:
            self.tx = CTransaction()
        self.inputs = []
        self.outputs = []
        self.unknown = {}

    def deserialize(self, psbt):
        hexstring = Base64ToHex(psbt.strip())
        f = BufferedReader(BytesIO(binascii.unhexlify(hexstring)))
        end = len(binascii.unhexlify(hexstring))

        # Read the magic bytes
        magic = f.read(5)
        if magic != b"psbt\xff":
            raise PSBTSerializationError("invalid magic")

        # Read loop
        while True:
            # read the key
            try:
                key = deser_string(f)
            except Exception:
                break

            # Check for separator
            if len(key) == 0:
                break

            # First byte of key is the type
            key_type = struct.unpack("b", bytearray([key[0]]))[0]

            # Do stuff based on type
            if key_type == 0x00:
                # Checks for correctness
                if not self.tx.is_null:
                    raise PSBTSerializationError(
                        "Duplicate key, unsigned tx already provided"
                    )
                elif len(key) > 1:
                    raise PSBTSerializationError(
                        "Global unsigned tx key is more than one byte type"
                    )

                # read in value
                value = BufferedReader(BytesIO(deser_string(f)))
                self.tx.deserialize(value)

                # Make sure that all scriptSigs and scriptWitnesses are empty
                for txin in self.tx.vin:
                    if len(txin.scriptSig) != 0 or not self.tx.wit.is_null():
                        raise PSBTSerializationError(
                            "Unsigned tx does not have empty scriptSigs and scriptWitnesses"
                        )

            else:
                if key in self.unknown:
                    raise PSBTSerializationError(
                        "Duplicate key, key for unknown value already provided"
                    )
                value = deser_string(f)
                self.unknown[key] = value

        # make sure that we got an unsigned tx
        if self.tx.is_null():
            raise PSBTSerializationError("No unsigned trasaction was provided")

        # Read input data
        for txin in self.tx.vin:
            if f.tell() == end:
                break
            input = PartiallySignedInput()
            input.deserialize(f)
            self.inputs.append(input)

            if (
                input.non_witness_utxo
                and input.non_witness_utxo.rehash()
                and input.non_witness_utxo.sha256 != txin.prevout.sha256
            ):
                raise PSBTSerializationError(
                    "Non-witness UTXO does not match outpoint hash"
                )

        if len(self.inputs) != len(self.tx.vin):
            raise PSBTSerializationError(
                "Inputs provided does not match the number of inputs in transaction"
            )

        # Read output data
        for txout in self.tx.vout:
            if f.tell() == end:
                break
            output = PartiallySignedOutput()
            output.deserialize(f)
            self.outputs.append(output)

        if len(self.outputs) != len(self.tx.vout):
            raise PSBTSerializationError(
                "Outputs provided does not match the number of outputs in transaction"
            )

    def serialize(self):
        r = b""

        # magic bytes
        r += b"psbt\xff"

        # unsigned tx flag
        r += b"\x01\x00"

        # write serialized tx
        tx = self.tx.serialize_with_witness()
        r += ser_compact_size(len(tx))
        r += tx

        # unknowns
        for key, value in sorted(self.unknown.items()):
            r += ser_string(key)
            r += ser_string(value)

        # separator
        r += b"\x00"

        # inputs
        for input in self.inputs:
            r += input.serialize()

        # outputs
        for output in self.outputs:
            r += output.serialize()

        # return hex string
        return HexToBase64(binascii.hexlify(r)).decode()


# An extended public key (xpub) or private key (xprv). Just a data container for now.
# Only handles deserialization of extended keys into component data to be handled by something else
class ExtendedKey(object):

    MAINNET_PUBLIC = b"\x04\x88\xB2\x1E"
    MAINNET_PRIVATE = b"\x04\x88\xAD\xE4"
    TESTNET_PUBLIC = b"\x04\x35\x87\xCF"
    TESTNET_PRIVATE = b"\x04\x35\x83\x94"

    def __init__(self):
        self.is_testnet = False
        self.is_private = False
        self.depth = 0
        self.parent_fingerprint = b""
        self.child_num = 0
        self.chaincode = b""
        self.pubkey = b""
        self.privkey = b""

    def deserialize(self, xpub: str):
        data = base58.decode(xpub)[:-4]  # Decoded xpub without checksum

        version = data[0:4]
        if (
            version == ExtendedKey.TESTNET_PUBLIC
            or version == ExtendedKey.TESTNET_PRIVATE
        ):
            self.is_testnet = True
        if (
            version == ExtendedKey.MAINNET_PRIVATE
            or version == ExtendedKey.TESTNET_PRIVATE
        ):
            self.is_private = True

        self.depth = data[4]
        self.parent_fingerprint = data[5:9]
        self.child_num = struct.unpack(">I", data[9:13])[0]
        self.chaincode = data[13:45]

        if self.is_private:
            self.privkey = data[46:]
        else:
            self.pubkey = data[45:78]

    def get_printable_dict(self):
        d = {}
        d["testnet"] = self.is_testnet
        d["private"] = self.is_private
        d["depth"] = self.depth
        d["parent_fingerprint"] = binascii.hexlify(self.parent_fingerprint).decode()
        d["child_num"] = self.child_num
        d["chaincode"] = binascii.hexlify(self.chaincode).decode()
        if self.is_private:
            d["privkey"] = binascii.hexlify(self.privkey).decode()
        else:
            d["pubkey"] = binascii.hexlify(self.pubkey).decode()
        return d
