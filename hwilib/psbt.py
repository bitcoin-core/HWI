"""
PSBT Classes and Utilities
**************************
"""

import base64
import struct

from io import BytesIO, BufferedReader
from typing import (
    Dict,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
)

from .key import KeyOriginInfo
from .errors import PSBTSerializationError
from .tx import (
    CTransaction,
    CTxInWitness,
    CTxOut,
)
from ._serialize import (
    deser_string,
    Readable,
    ser_compact_size,
    ser_string,
)

def DeserializeHDKeypath(
    f: Readable,
    key: bytes,
    hd_keypaths: MutableMapping[bytes, KeyOriginInfo],
    expected_sizes: Sequence[int],
) -> None:
    """
    :meta private:

    Deserialize a serialized PSBT public key and keypath key-value pair.

    :param f: The byte stream to read the value from.
    :param key: The bytes of the key of the key-value pair.
    :param hd_keypaths: Dictionary of public key bytes to their :class:`~hwilib.key.KeyOriginInfo`.
    :param expected_sizes: List of key lengths expected for the keypair being deserialized.
    """
    if len(key) not in expected_sizes:
        raise PSBTSerializationError("Size of key was not the expected size for the type partial signature pubkey. Length: {}".format(len(key)))
    pubkey = key[1:]
    if pubkey in hd_keypaths:
        raise PSBTSerializationError("Duplicate key, input partial signature for pubkey already provided")

    hd_keypaths[pubkey] = KeyOriginInfo.deserialize(deser_string(f))

def SerializeHDKeypath(hd_keypaths: Mapping[bytes, KeyOriginInfo], type: bytes) -> bytes:
    """
    :meta private:

    Serialize a public key to :class:`~hwilib.key.KeyOriginInfo` mapping as a PSBT key-value pair.

    :param hd_keypaths: The mapping of public key to keypath
    :param type: The PSBT type bytes to use
    :returns: The serialized keypaths
    """
    r = b""
    for pubkey, path in sorted(hd_keypaths.items()):
        r += ser_string(type + pubkey)
        packed = path.serialize()
        r += ser_string(packed)
    return r

class PartiallySignedInput:
    """
    An object for a PSBT input map.
    """
    def __init__(self) -> None:
        self.non_witness_utxo: Optional[CTransaction] = None
        self.witness_utxo: Optional[CTxOut] = None
        self.partial_sigs: Dict[bytes, bytes] = {}
        self.sighash = 0
        self.redeem_script = b""
        self.witness_script = b""
        self.hd_keypaths: Dict[bytes, KeyOriginInfo] = {}
        self.final_script_sig = b""
        self.final_script_witness = CTxInWitness()
        self.unknown: Dict[bytes, bytes] = {}

    def set_null(self) -> None:
        """
        Clear all values in this PSBT input map.
        """
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

    def deserialize(self, f: Readable) -> None:
        """
        Deserialize a serialized PSBT input.

        :param f: A byte stream containing the serialized PSBT input
        """
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
                    raise PSBTSerializationError("Duplicate Key, input non witness utxo already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("non witness utxo key is more than one byte type")
                self.non_witness_utxo = CTransaction()
                utxo_bytes = BufferedReader(BytesIO(deser_string(f))) # type: ignore
                self.non_witness_utxo.deserialize(utxo_bytes)
                self.non_witness_utxo.rehash()

            elif key_type == 1:
                if self.witness_utxo:
                    raise PSBTSerializationError("Duplicate Key, input witness utxo already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("witness utxo key is more than one byte type")
                self.witness_utxo = CTxOut()
                tx_out_bytes = BufferedReader(BytesIO(deser_string(f))) # type: ignore
                self.witness_utxo.deserialize(tx_out_bytes)

            elif key_type == 2:
                if len(key) != 34 and len(key) != 66:
                    raise PSBTSerializationError("Size of key was not the expected size for the type partial signature pubkey")
                pubkey = key[1:]
                if pubkey in self.partial_sigs:
                    raise PSBTSerializationError("Duplicate key, input partial signature for pubkey already provided")

                sig = deser_string(f)
                self.partial_sigs[pubkey] = sig

            elif key_type == 3:
                if self.sighash > 0:
                    raise PSBTSerializationError("Duplicate key, input sighash type already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("sighash key is more than one byte type")
                sighash_bytes = deser_string(f)
                self.sighash = struct.unpack("<I", sighash_bytes)[0]

            elif key_type == 4:
                if len(self.redeem_script) != 0:
                    raise PSBTSerializationError("Duplicate key, input redeemScript already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("redeemScript key is more than one byte type")
                self.redeem_script = deser_string(f)

            elif key_type == 5:
                if len(self.witness_script) != 0:
                    raise PSBTSerializationError("Duplicate key, input witnessScript already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("witnessScript key is more than one byte type")
                self.witness_script = deser_string(f)

            elif key_type == 6:
                DeserializeHDKeypath(f, key, self.hd_keypaths, [34, 66])

            elif key_type == 7:
                if len(self.final_script_sig) != 0:
                    raise PSBTSerializationError("Duplicate key, input final scriptSig already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("final scriptSig key is more than one byte type")
                self.final_script_sig = deser_string(f)

            elif key_type == 8:
                if not self.final_script_witness.is_null():
                    raise PSBTSerializationError("Duplicate key, input final scriptWitness already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("final scriptWitness key is more than one byte type")
                witness_bytes = BufferedReader(BytesIO(deser_string(f))) # type: ignore
                self.final_script_witness.deserialize(witness_bytes)

            else:
                if key in self.unknown:
                    raise PSBTSerializationError("Duplicate key, key for unknown value already provided")
                unknown_bytes = deser_string(f)
                self.unknown[key] = unknown_bytes

    def serialize(self) -> bytes:
        """
        Serialize this PSBT input

        :returns: The serialized PSBT input
        """
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
    """
    An object for a PSBT output map.
    """
    def __init__(self) -> None:
        self.redeem_script = b""
        self.witness_script = b""
        self.hd_keypaths: Dict[bytes, KeyOriginInfo] = {}
        self.unknown: Dict[bytes, bytes] = {}

    def set_null(self) -> None:
        """
        Clear this PSBT output map
        """
        self.redeem_script = b""
        self.witness_script = b""
        self.hd_keypaths.clear()
        self.unknown.clear()

    def deserialize(self, f: Readable) -> None:
        """
        Deserialize a serialized PSBT output map

        :param f: A byte stream containing the serialized PSBT output
        """
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
                    raise PSBTSerializationError("Duplicate key, output redeemScript already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Output redeemScript key is more than one byte type")
                self.redeem_script = deser_string(f)

            elif key_type == 1:
                if len(self.witness_script) != 0:
                    raise PSBTSerializationError("Duplicate key, output witnessScript already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Output witnessScript key is more than one byte type")
                self.witness_script = deser_string(f)

            elif key_type == 2:
                DeserializeHDKeypath(f, key, self.hd_keypaths, [34, 66])

            else:
                if key in self.unknown:
                    raise PSBTSerializationError("Duplicate key, key for unknown value already provided")
                value = deser_string(f)
                self.unknown[key] = value

    def serialize(self) -> bytes:
        """
        Serialize this PSBT output

        :returns: The serialized PSBT output
        """
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
    """
    A class representing a PSBT
    """

    def __init__(self, tx: Optional[CTransaction] = None) -> None:
        """
        :param tx: A Bitcoin transaction that specifies the inputs and outputs to use
        """
        if tx:
            self.tx = tx
        else:
            self.tx = CTransaction()
        self.inputs: List[PartiallySignedInput] = []
        self.outputs: List[PartiallySignedOutput] = []
        self.unknown: Dict[bytes, bytes] = {}
        self.xpub: Dict[bytes, KeyOriginInfo] = {}

    def deserialize(self, psbt: str) -> None:
        """
        Deserialize a base 64 encoded PSBT.

        :param psbt: A base 64 PSBT.
        """
        psbt_bytes = base64.b64decode(psbt.strip())
        f = BufferedReader(BytesIO(psbt_bytes)) # type: ignore
        end = len(psbt_bytes)

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
                    raise PSBTSerializationError("Duplicate key, unsigned tx already provided")
                elif len(key) > 1:
                    raise PSBTSerializationError("Global unsigned tx key is more than one byte type")

                # read in value
                tx_bytes = BufferedReader(BytesIO(deser_string(f))) # type: ignore
                self.tx.deserialize(tx_bytes)

                # Make sure that all scriptSigs and scriptWitnesses are empty
                for txin in self.tx.vin:
                    if len(txin.scriptSig) != 0 or not self.tx.wit.is_null():
                        raise PSBTSerializationError("Unsigned tx does not have empty scriptSigs and scriptWitnesses")
            elif key_type == 0x01:
                DeserializeHDKeypath(f, key, self.xpub, [79])
            else:
                if key in self.unknown:
                    raise PSBTSerializationError("Duplicate key, key for unknown value already provided")
                unknown_bytes = deser_string(f)
                self.unknown[key] = unknown_bytes

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

            if input.non_witness_utxo:
                input.non_witness_utxo.rehash()
                if input.non_witness_utxo.sha256 != txin.prevout.hash:
                    raise PSBTSerializationError("Non-witness UTXO does not match outpoint hash")

        if (len(self.inputs) != len(self.tx.vin)):
            raise PSBTSerializationError("Inputs provided does not match the number of inputs in transaction")

        # Read output data
        for txout in self.tx.vout:
            if f.tell() == end:
                break
            output = PartiallySignedOutput()
            output.deserialize(f)
            self.outputs.append(output)

        if len(self.outputs) != len(self.tx.vout):
            raise PSBTSerializationError("Outputs provided does not match the number of outputs in transaction")

    def serialize(self) -> str:
        """
        Serialize the PSBT as a base 64 encoded string.

        :returns: The base 64 encoded string.
        """
        r = b""

        # magic bytes
        r += b"psbt\xff"

        # unsigned tx flag
        r += b"\x01\x00"

        # write serialized tx
        tx = self.tx.serialize_with_witness()
        r += ser_compact_size(len(tx))
        r += tx

        # write xpubs
        r += SerializeHDKeypath(self.xpub, b"\x01")

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
        return base64.b64encode(r).decode()
