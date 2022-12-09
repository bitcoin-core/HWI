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
    Set,
    Tuple,
)

from .key import KeyOriginInfo
from .errors import PSBTSerializationError
from .tx import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from ._serialize import (
    deser_compact_size,
    deser_string,
    Readable,
    ser_compact_size,
    ser_string,
    ser_uint256,
    uint256_from_str,
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

    PSBT_IN_NON_WITNESS_UTXO = 0x00
    PSBT_IN_WITNESS_UTXO = 0x01
    PSBT_IN_PARTIAL_SIG = 0x02
    PSBT_IN_SIGHASH_TYPE = 0x03
    PSBT_IN_REDEEM_SCRIPT = 0x04
    PSBT_IN_WITNESS_SCRIPT = 0x05
    PSBT_IN_BIP32_DERIVATION = 0x06
    PSBT_IN_FINAL_SCRIPTSIG = 0x07
    PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
    PSBT_IN_PREVIOUS_TXID = 0x0e
    PSBT_IN_OUTPUT_INDEX = 0x0f
    PSBT_IN_SEQUENCE = 0x10
    PSBT_IN_REQUIRED_TIME_LOCKTIME = 0x11
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12
    PSBT_IN_TAP_KEY_SIG = 0x13
    PSBT_IN_TAP_SCRIPT_SIG = 0x14
    PSBT_IN_TAP_LEAF_SCRIPT = 0x15
    PSBT_IN_TAP_BIP32_DERIVATION = 0x16
    PSBT_IN_TAP_INTERNAL_KEY = 0x17
    PSBT_IN_TAP_MERKLE_ROOT = 0x18

    def __init__(self, version: int) -> None:
        self.non_witness_utxo: Optional[CTransaction] = None
        self.witness_utxo: Optional[CTxOut] = None
        self.partial_sigs: Dict[bytes, bytes] = {}
        self.sighash: Optional[int] = None
        self.redeem_script = b""
        self.witness_script = b""
        self.hd_keypaths: Dict[bytes, KeyOriginInfo] = {}
        self.final_script_sig = b""
        self.final_script_witness = CTxInWitness()
        self.prev_txid = b""
        self.prev_out: Optional[int] = None
        self.sequence: Optional[int] = None
        self.time_locktime: Optional[int] = None
        self.height_locktime: Optional[int] = None
        self.tap_key_sig = b""
        self.tap_script_sigs: Dict[Tuple[bytes, bytes], bytes] = {}
        self.tap_scripts: Dict[Tuple[bytes, int], Set[bytes]] = {}
        self.tap_bip32_paths: Dict[bytes, Tuple[Set[bytes], KeyOriginInfo]] = {}
        self.tap_internal_key = b""
        self.tap_merkle_root = b""
        self.unknown: Dict[bytes, bytes] = {}

        self.version: int = version

    def set_null(self) -> None:
        """
        Clear all values in this PSBT input map.
        """
        self.non_witness_utxo = None
        self.witness_utxo = None
        self.partial_sigs.clear()
        self.sighash = None
        self.redeem_script = b""
        self.witness_script = b""
        self.hd_keypaths.clear()
        self.final_script_sig = b""
        self.final_script_witness = CTxInWitness()
        self.tap_key_sig = b""
        self.tap_script_sigs.clear()
        self.tap_scripts.clear()
        self.tap_bip32_paths.clear()
        self.tap_internal_key = b""
        self.tap_merkle_root = b""
        self.prev_txid = b""
        self.prev_out = None
        self.sequence = None
        self.time_locktime = None
        self.height_locktime = None
        self.unknown.clear()

    def deserialize(self, f: Readable) -> None:
        """
        Deserialize a serialized PSBT input.

        :param f: A byte stream containing the serialized PSBT input
        """
        key_lookup: Set[bytes] = set()

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
            key_type = deser_compact_size(BytesIO(key))

            if key_type == PartiallySignedInput.PSBT_IN_NON_WITNESS_UTXO:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate Key, input non witness utxo already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("non witness utxo key is more than one byte type")
                self.non_witness_utxo = CTransaction()
                utxo_bytes = BufferedReader(BytesIO(deser_string(f))) # type: ignore
                self.non_witness_utxo.deserialize(utxo_bytes)
                self.non_witness_utxo.rehash()
            elif key_type == PartiallySignedInput.PSBT_IN_WITNESS_UTXO:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate Key, input witness utxo already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("witness utxo key is more than one byte type")
                self.witness_utxo = CTxOut()
                tx_out_bytes = BufferedReader(BytesIO(deser_string(f))) # type: ignore
                self.witness_utxo.deserialize(tx_out_bytes)
            elif key_type == PartiallySignedInput.PSBT_IN_PARTIAL_SIG:
                if len(key) != 34 and len(key) != 66:
                    raise PSBTSerializationError("Size of key was not the expected size for the type partial signature pubkey")
                pubkey = key[1:]
                if pubkey in self.partial_sigs:
                    raise PSBTSerializationError("Duplicate key, input partial signature for pubkey already provided")

                sig = deser_string(f)
                self.partial_sigs[pubkey] = sig
            elif key_type == PartiallySignedInput.PSBT_IN_SIGHASH_TYPE:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input sighash type already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("sighash key is more than one byte type")
                sighash_bytes = deser_string(f)
                self.sighash = struct.unpack("<I", sighash_bytes)[0]
            elif key_type == PartiallySignedInput.PSBT_IN_REDEEM_SCRIPT:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input redeemScript already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("redeemScript key is more than one byte type")
                self.redeem_script = deser_string(f)
            elif key_type == PartiallySignedInput.PSBT_IN_WITNESS_SCRIPT:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input witnessScript already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("witnessScript key is more than one byte type")
                self.witness_script = deser_string(f)
            elif key_type == PartiallySignedInput.PSBT_IN_BIP32_DERIVATION:
                DeserializeHDKeypath(f, key, self.hd_keypaths, [34, 66])
            elif key_type == PartiallySignedInput.PSBT_IN_FINAL_SCRIPTSIG:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input final scriptSig already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("final scriptSig key is more than one byte type")
                self.final_script_sig = deser_string(f)
            elif key_type == PartiallySignedInput.PSBT_IN_FINAL_SCRIPTWITNESS:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input final scriptWitness already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("final scriptWitness key is more than one byte type")
                witness_bytes = BufferedReader(BytesIO(deser_string(f))) # type: ignore
                self.final_script_witness.deserialize(witness_bytes)
            elif key_type == PartiallySignedInput.PSBT_IN_PREVIOUS_TXID:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input previous txid is already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Previous txid key is more than one byte type")
                txid = deser_string(f)
                if len(txid) != 32:
                    raise PSBTSerializationError("Previous txid is not 32 bytes")
                self.prev_txid = txid
            elif key_type == PartiallySignedInput.PSBT_IN_OUTPUT_INDEX:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input previous output index is already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Previous output index key is more than one byte type")
                v = deser_string(f)
                if len(v) != 4:
                    raise PSBTSerializationError("Previous output index is not 4 bytes")
                self.prev_out = struct.unpack("<I", v)[0]
            elif key_type == PartiallySignedInput.PSBT_IN_SEQUENCE:
                pass
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input sequence is already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Input sequence key is more than one byte type")
                v = deser_string(f)
                if len(v) != 4:
                    raise PSBTSerializationError("Input sequence is not 4 bytes")
                self.sequence = struct.unpack("<I", v)[0]
            elif key_type == PartiallySignedInput.PSBT_IN_REQUIRED_TIME_LOCKTIME:
                pass
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input required time based locktime is already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Input time based locktime key is more than one byte type")
                v = deser_string(f)
                if len(v) != 4:
                    raise PSBTSerializationError("Input time based locktime is not 4 bytes")
                self.time_locktime = struct.unpack("<I", v)[0]
            elif key_type == PartiallySignedInput.PSBT_IN_REQUIRED_HEIGHT_LOCKTIME:
                pass
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input required height based locktime index is already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Input height based locktime key is more than one byte type")
                v = deser_string(f)
                if len(v) != 4:
                    raise PSBTSerializationError("Input height based locktime is not 4 bytes")
                self.height_locktime = struct.unpack("<I", v)[0]
            elif key_type == PartiallySignedInput.PSBT_IN_TAP_KEY_SIG:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input Taproot key signature already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Input Taproot key signature key is more than one byte type")
                self.tap_key_sig = deser_string(f)
                if len(self.tap_key_sig) < 64:
                    raise PSBTSerializationError("Input Taproot key path signature is shorter than 64 bytes")
                elif len(self.tap_key_sig) > 65:
                    raise PSBTSerializationError("Input Taproot key path signature is longer than 65 bytes")
            elif key_type == PartiallySignedInput.PSBT_IN_TAP_SCRIPT_SIG:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input Taproot script signature already provided")
                elif len(key) != 65:
                    raise PSBTSerializationError("Input Taproot script signature key is not 65 bytes")
                xonly = key[1:33]
                script_hash = key[33:65]
                sig = deser_string(f)
                if len(sig) < 64:
                    raise PSBTSerializationError("Input Taproot script path signature is shorter than 64 bytes")
                elif len(sig) > 65:
                    raise PSBTSerializationError("Input Taproot script path signature is longer than 65 bytes")
                self.tap_script_sigs[(xonly, script_hash)] = sig
            elif key_type == PartiallySignedInput.PSBT_IN_TAP_LEAF_SCRIPT:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input Taproot leaf script already provided")
                elif len(key) < 34:
                    raise PSBTSerializationError("Input Taproot leaf script key is not at least 34 bytes")
                elif (len(key) - 2) % 32 != 0:
                    raise PSBTSerializationError("Input Taproot leaf script key's control block is not valid")
                script = deser_string(f)
                if len(script) == 0:
                    raise PSBTSerializationError("Input Taproot leaf script cannot be empty")
                leaf_script = (script[:-1], int(script[-1]))
                if leaf_script not in self.tap_scripts:
                    self.tap_scripts[leaf_script] = set()
                self.tap_scripts[(script[:-1], int(script[-1]))].add(key[1:])
            elif key_type == PartiallySignedInput.PSBT_IN_TAP_BIP32_DERIVATION:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input Taproot BIP 32 keypath already provided")
                elif len(key) != 33:
                    raise PSBTSerializationError("Input Taproot BIP 32 keypath key is not 33 bytes")
                xonly = key[1:33]
                value = deser_string(f)
                vs = BytesIO(value)
                num_hashes = deser_compact_size(vs)
                leaf_hashes = set()
                for i in range(0, num_hashes):
                    leaf_hashes.add(vs.read(32))
                self.tap_bip32_paths[xonly] = (leaf_hashes, KeyOriginInfo.deserialize(vs.read()))
            elif key_type == PartiallySignedInput.PSBT_IN_TAP_INTERNAL_KEY:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input Taproot internal key already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Input Taproot internal key key is more than one byte type")
                self.tap_internal_key = deser_string(f)
                if len(self.tap_internal_key) != 32:
                    raise PSBTSerializationError("Input Taproot internal key is not 32 bytes")
            elif key_type == PartiallySignedInput.PSBT_IN_TAP_MERKLE_ROOT:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, input Taproot merkle root already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Input Taproot merkle root key is more than one byte type")
                self.tap_merkle_root = deser_string(f)
                if len(self.tap_merkle_root) != 32:
                    raise PSBTSerializationError("Input Taproot merkle root is not 32 bytes")
            else:
                if key in self.unknown:
                    raise PSBTSerializationError("Duplicate key, key for unknown value already provided")
                unknown_bytes = deser_string(f)
                self.unknown[key] = unknown_bytes

            key_lookup.add(key)

        # Make sure required PSBTv2 fields are present
        if self.version >= 2:
            if len(self.prev_txid) == 0:
                raise PSBTSerializationError("Previous TXID is required in PSBTv2")
            if self.prev_out is None:
                raise PSBTSerializationError("Previous output's index is required in PSBTv2")

    def serialize(self) -> bytes:
        """
        Serialize this PSBT input

        :returns: The serialized PSBT input
        """
        r = b""

        if self.non_witness_utxo:
            r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_NON_WITNESS_UTXO))
            tx = self.non_witness_utxo.serialize_with_witness()
            r += ser_string(tx)

        if self.witness_utxo:
            r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_WITNESS_UTXO))
            tx = self.witness_utxo.serialize()
            r += ser_string(tx)

        if len(self.final_script_sig) == 0 and self.final_script_witness.is_null():
            for pubkey, sig in sorted(self.partial_sigs.items()):
                r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_PARTIAL_SIG) + pubkey)
                r += ser_string(sig)

            if self.sighash is not None:
                r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_SIGHASH_TYPE))
                r += ser_string(struct.pack("<I", self.sighash))

            if len(self.redeem_script) != 0:
                r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_REDEEM_SCRIPT))
                r += ser_string(self.redeem_script)

            if len(self.witness_script) != 0:
                r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_WITNESS_SCRIPT))
                r += ser_string(self.witness_script)

            r += SerializeHDKeypath(self.hd_keypaths, ser_compact_size(PartiallySignedInput.PSBT_IN_BIP32_DERIVATION))

            if len(self.tap_key_sig) != 0:
                r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_TAP_KEY_SIG))
                r += ser_string(self.tap_key_sig)

            for (xonly, leaf_hash), sig in self.tap_script_sigs.items():
                r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_TAP_SCRIPT_SIG) + xonly + leaf_hash)
                r += ser_string(sig)

            for (script, leaf_ver), control_blocks in self.tap_scripts.items():
                for control_block in control_blocks:
                    r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_TAP_LEAF_SCRIPT) + control_block)
                    r += ser_string(script + struct.pack("B", leaf_ver))

            for xonly, (leaf_hashes, origin) in self.tap_bip32_paths.items():
                r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_TAP_BIP32_DERIVATION) + xonly)
                value = ser_compact_size(len(leaf_hashes))
                for lh in leaf_hashes:
                    value += lh
                value += origin.serialize()
                r += ser_string(value)

            if len(self.tap_internal_key) != 0:
                r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_TAP_INTERNAL_KEY))
                r += ser_string(self.tap_internal_key)

            if len(self.tap_merkle_root) != 0:
                r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_TAP_MERKLE_ROOT))
                r += ser_string(self.tap_merkle_root)

        if len(self.final_script_sig) != 0:
            r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_FINAL_SCRIPTSIG))
            r += ser_string(self.final_script_sig)

        if not self.final_script_witness.is_null():
            r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_FINAL_SCRIPTWITNESS))
            witstack = self.final_script_witness.serialize()
            r += ser_string(witstack)

        if self.version >= 2:
            if len(self.prev_txid) != 0:
                r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_PREVIOUS_TXID))
                r += ser_string(self.prev_txid)

            if self.prev_out is not None:
                r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_OUTPUT_INDEX))
                r += ser_string(struct.pack("<I", self.prev_out))

            if self.sequence is not None:
                r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_SEQUENCE))
                r += ser_string(struct.pack("<I", self.sequence))

            if self.time_locktime is not None:
                r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_REQUIRED_TIME_LOCKTIME))
                r += ser_string(struct.pack("<I", self.time_locktime))

            if self.height_locktime is not None:
                r += ser_string(ser_compact_size(PartiallySignedInput.PSBT_IN_REQUIRED_HEIGHT_LOCKTIME))
                r += ser_string(struct.pack("<I", self.height_locktime))

        for key, value in sorted(self.unknown.items()):
            r += ser_string(key)
            r += ser_string(value)

        r += b"\x00"

        return r

class PartiallySignedOutput:
    """
    An object for a PSBT output map.
    """

    PSBT_OUT_REDEEM_SCRIPT = 0x00
    PSBT_OUT_WITNESS_SCRIPT = 0x01
    PSBT_OUT_BIP32_DERIVATION = 0x02
    PSBT_OUT_AMOUNT = 0x03
    PSBT_OUT_SCRIPT = 0x04
    PSBT_OUT_TAP_INTERNAL_KEY = 0x05
    PSBT_OUT_TAP_TREE = 0x06
    PSBT_OUT_TAP_BIP32_DERIVATION = 0x07

    def __init__(self, version: int) -> None:
        self.redeem_script = b""
        self.witness_script = b""
        self.hd_keypaths: Dict[bytes, KeyOriginInfo] = {}
        self.amount: Optional[int] = None
        self.script = b""
        self.tap_internal_key = b""
        self.tap_tree = b""
        self.tap_bip32_paths: Dict[bytes, Tuple[Set[bytes], KeyOriginInfo]] = {}
        self.unknown: Dict[bytes, bytes] = {}

        self.version: int = version

    def set_null(self) -> None:
        """
        Clear this PSBT output map
        """
        self.redeem_script = b""
        self.witness_script = b""
        self.hd_keypaths.clear()
        self.tap_internal_key = b""
        self.tap_tree = b""
        self.tap_bip32_paths.clear()
        self.amount = None
        self.script = b""
        self.unknown.clear()

    def deserialize(self, f: Readable) -> None:
        """
        Deserialize a serialized PSBT output map

        :param f: A byte stream containing the serialized PSBT output
        """
        key_lookup: Set[bytes] = set()

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
            key_type = deser_compact_size(BytesIO(key))

            if key_type == PartiallySignedOutput.PSBT_OUT_REDEEM_SCRIPT:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, output redeemScript already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Output redeemScript key is more than one byte type")
                self.redeem_script = deser_string(f)
            elif key_type == PartiallySignedOutput.PSBT_OUT_WITNESS_SCRIPT:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, output witnessScript already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Output witnessScript key is more than one byte type")
                self.witness_script = deser_string(f)
            elif key_type == PartiallySignedOutput.PSBT_OUT_BIP32_DERIVATION:
                DeserializeHDKeypath(f, key, self.hd_keypaths, [34, 66])
            elif key_type == PartiallySignedOutput.PSBT_OUT_AMOUNT:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, output amount already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Output amount key is more than one byte type")
                v = deser_string(f)
                if len(v) != 8:
                    raise PSBTSerializationError("Output amount is not 8 bytes")
                self.amount = struct.unpack("<q", v)[0]
            elif key_type == PartiallySignedOutput.PSBT_OUT_SCRIPT:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, output script already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Output script key is more than one byte type")
                self.script = deser_string(f)
            elif key_type == PartiallySignedOutput.PSBT_OUT_TAP_INTERNAL_KEY:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, output Taproot internal key already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Output Taproot internal key key is more than one byte type")
                self.tap_internal_key = deser_string(f)
                if len(self.tap_internal_key) != 32:
                    raise PSBTSerializationError("Output Taproot internal key is not 32 bytes")
            elif key_type == PartiallySignedOutput.PSBT_OUT_TAP_TREE:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, output Taproot tree already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Output Taproot tree key is more than one byte type")
                self.tap_tree = deser_string(f)
            elif key_type == PartiallySignedOutput.PSBT_OUT_TAP_BIP32_DERIVATION:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, output Taproot BIP 32 keypath already provided")
                elif len(key) != 33:
                    raise PSBTSerializationError("Output Taproot BIP 32 keypath key is not 33 bytes")
                xonly = key[1:33]
                value = deser_string(f)
                vs = BytesIO(value)
                num_hashes = deser_compact_size(vs)
                leaf_hashes = set()
                for i in range(0, num_hashes):
                    leaf_hashes.add(vs.read(32))
                self.tap_bip32_paths[xonly] = (leaf_hashes, KeyOriginInfo.deserialize(vs.read()))
            else:
                if key in self.unknown:
                    raise PSBTSerializationError("Duplicate key, key for unknown value already provided")
                value = deser_string(f)
                self.unknown[key] = value

            key_lookup.add(key)

        # Make sure required PSBTv2 fields are present
        if self.version >= 2:
            if self.amount is None:
                raise PSBTSerializationError("PSBT_OUTPUT_AMOUNT is required in PSBTv2")
            if len(self.script) == 0:
                raise PSBTSerializationError("PSBT_OUTPUT_SCRIPT is required in PSBTv2")

    def serialize(self) -> bytes:
        """
        Serialize this PSBT output

        :returns: The serialized PSBT output
        """
        r = b""
        if len(self.redeem_script) != 0:
            r += ser_string(ser_compact_size(PartiallySignedOutput.PSBT_OUT_REDEEM_SCRIPT))
            r += ser_string(self.redeem_script)

        if len(self.witness_script) != 0:
            r += ser_string(ser_compact_size(PartiallySignedOutput.PSBT_OUT_WITNESS_SCRIPT))
            r += ser_string(self.witness_script)

        r += SerializeHDKeypath(self.hd_keypaths, ser_compact_size(PartiallySignedOutput.PSBT_OUT_BIP32_DERIVATION))

        if self.version >= 2:
            if self.amount is not None:
                r += ser_string(ser_compact_size(PartiallySignedOutput.PSBT_OUT_AMOUNT))
                r += ser_string(struct.pack("<q", self.amount))

            if len(self.script) != 0:
                r += ser_string(ser_compact_size(PartiallySignedOutput.PSBT_OUT_SCRIPT))
                r += ser_string(self.script)

        if len(self.tap_internal_key) != 0:
            r += ser_string(ser_compact_size(PartiallySignedOutput.PSBT_OUT_TAP_INTERNAL_KEY))
            r += ser_string(self.tap_internal_key)

        if len(self.tap_tree) != 0:
            r += ser_string(ser_compact_size(PartiallySignedOutput.PSBT_OUT_TAP_TREE))
            r += ser_string(self.tap_tree)

        for xonly, (leaf_hashes, origin) in self.tap_bip32_paths.items():
            r += ser_string(ser_compact_size(PartiallySignedOutput.PSBT_OUT_TAP_BIP32_DERIVATION) + xonly)
            value = ser_compact_size(len(leaf_hashes))
            for lh in leaf_hashes:
                value += lh
            value += origin.serialize()
            r += ser_string(value)

        for key, value in sorted(self.unknown.items()):
            r += ser_string(key)
            r += ser_string(value)

        r += b"\x00"

        return r

    def get_txout(self) -> CTxOut:
        """
        Creates a CTxOut for this output

        :returns: The CTxOut
        """
        assert self.amount is not None
        assert len(self.script) != 0
        return CTxOut(self.amount, self.script)

class PSBT(object):
    """
    A class representing a PSBT
    """

    PSBT_GLOBAL_UNSIGNED_TX = 0x00
    PSBT_GLOBAL_XPUB = 0x01
    PSBT_GLOBAL_TX_VERSION = 0x02
    PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03
    PSBT_GLOBAL_INPUT_COUNT = 0x04
    PSBT_GLOBAL_OUTPUT_COUNT = 0x05
    PSBT_GLOBAL_TX_MODIFIABLE = 0x06
    PSBT_GLOBAL_VERSION = 0xFB

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
        self.tx_version: Optional[int] = None
        self.fallback_locktime: Optional[int] = None
        self.tx_modifiable: Optional[int] = None

        # Assume version 0 PSBT
        self.version = 0
        self.explicit_version = False

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

        key_lookup: Set[bytes] = set()

        input_count = None
        output_count = None

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
            key_type = deser_compact_size(BytesIO(key))

            # Do stuff based on type
            if key_type == PSBT.PSBT_GLOBAL_UNSIGNED_TX:
                # Checks for correctness
                if key in key_lookup:
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
            elif key_type == PSBT.PSBT_GLOBAL_XPUB:
                DeserializeHDKeypath(f, key, self.xpub, [79])
            elif key_type == PSBT.PSBT_GLOBAL_TX_VERSION:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, global transaction version is already provided")
                elif len(key) > 1:
                    raise PSBTSerializationError("Global transaction version key is more than one byte type")
                v = deser_string(f)
                if len(v) != 4:
                    raise PSBTSerializationError("Global transaction version is not 4 bytes")
                self.tx_version = struct.unpack("<I", v)[0]
            elif key_type == PSBT.PSBT_GLOBAL_FALLBACK_LOCKTIME:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, global fallback locktime is already provided")
                elif len(key) > 1:
                    raise PSBTSerializationError("Global fallback locktime key is more than one byte type")
                v = deser_string(f)
                if len(v) != 4:
                    raise PSBTSerializationError("Global fallback locktime is not 4 bytes")
                self.fallback_locktime = struct.unpack("<I", v)[0]
            elif key_type == PSBT.PSBT_GLOBAL_INPUT_COUNT:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, global input count is already provided")
                elif len(key) > 1:
                    raise PSBTSerializationError("Global input count key is more than one byte type")
                _ = deser_compact_size(f) # Value length, we can ignore this
                input_count = deser_compact_size(f)
            elif key_type == PSBT.PSBT_GLOBAL_OUTPUT_COUNT:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, global output count is already provided")
                elif len(key) > 1:
                    raise PSBTSerializationError("Global output count key is more than one byte type")
                _ = deser_compact_size(f) # Value length, we can ignore this
                output_count = deser_compact_size(f)
            elif key_type == PSBT.PSBT_GLOBAL_TX_MODIFIABLE:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, global tx modifiable flags is already provided")
                elif len(key) > 1:
                    raise PSBTSerializationError("Global tx modifiable flags key is more than one byte type")
                v = deser_string(f)
                if len(v) != 1:
                    raise PSBTSerializationError("Global tx modifiable flags is not 1 bytes")
                self.tx_modifiable = struct.unpack("<B", v)[0]
            elif key_type == PSBT.PSBT_GLOBAL_VERSION:
                if key in key_lookup:
                    raise PSBTSerializationError("Duplicate key, global PSBT version is already provided")
                elif len(key) > 1:
                    raise PSBTSerializationError("Global PSBT version key is more than one byte type")
                v = deser_string(f)
                if len(v) != 4:
                    raise PSBTSerializationError("Global PSBT version is not 1 bytes")
                self.version = struct.unpack("<I", v)[0]
                self.explicit_version = True
            else:
                if key in self.unknown:
                    raise PSBTSerializationError("Duplicate key, key for unknown value already provided")
                unknown_bytes = deser_string(f)
                self.unknown[key] = unknown_bytes

            key_lookup.add(key)

        # Check PSBT version constraints
        if self.version == 0:
            # make sure that we got an unsigned tx
            if self.tx.is_null():
                raise PSBTSerializationError("No unsigned transaction was provided")
            # Make sure no v2 fields are present
            if self.tx_version is not None:
                raise PSBTSerializationError("PSBT_GLOBAL_TX_VERSION is not allowed in PSBTv0")
            if self.fallback_locktime is not None:
                raise PSBTSerializationError("PSBT_GLOBAL_FALLBACK_LOCKTIME is not allowed in PSBTv0")
            if input_count is not None:
                raise PSBTSerializationError("PSBT_GLOBAL_INPUT_COUNT is not allowed in PSBTv0")
            if output_count is not None:
                raise PSBTSerializationError("PSBT_GLOBAL_OUTPUT_COUNT is not allowed in PSBTv0")
            if self.tx_modifiable is not None:
                raise PSBTSerializationError("PSBT_GLOBAL_TX_MODIFIABLE is not allowed in PSBTv0")

        # Disallow v1
        if self.version == 1:
            raise PSBTSerializationError("There is no PSBT version 1")
        if self.version >= 2:
            # Tx version, input, and output counts are required
            if self.tx_version is None:
                raise PSBTSerializationError("PSBT_GLOBAL_TX_VERSION is required in PSBTv2")
            if input_count is None:
                raise PSBTSerializationError("PSBT_GLOBAL_INPUT_COUNT is required in PSBTv2")
            if output_count is None:
                raise PSBTSerializationError("PSBT_GLOBAL_OUTPUT_COUNT is required in PSBTv2")
            # Unsigned tx is disallowed
            if not self.tx.is_null():
                raise PSBTSerializationError("PSBT_GLOBAL_UNSIGNED_TX is not allowed in PSBTv2")

        # Read input data
        if input_count is None:
            input_count = len(self.tx.vin)
        for i in range(input_count):
            if f.tell() == end:
                break
            psbt_in = PartiallySignedInput(self.version)
            psbt_in.deserialize(f)
            self.inputs.append(psbt_in)

            if self.version >= 2:
                prev_txid = psbt_in.prev_txid
            else:
                prev_txid = ser_uint256(self.tx.vin[i].prevout.hash)

            if psbt_in.non_witness_utxo:
                psbt_in.non_witness_utxo.rehash()
                if psbt_in.non_witness_utxo.hash != prev_txid:
                    raise PSBTSerializationError("Non-witness UTXO does not match outpoint hash")

        if (len(self.inputs) != input_count):
            raise PSBTSerializationError("Inputs provided does not match the number of inputs in transaction")

        # Read output data
        if output_count is None:
            output_count = len(self.tx.vout)
        for i in range(output_count):
            if f.tell() == end:
                break
            output = PartiallySignedOutput(self.version)
            output.deserialize(f)
            self.outputs.append(output)

        if len(self.outputs) != output_count:
            raise PSBTSerializationError("Outputs provided does not match the number of outputs in transaction")

        self.cache_unsigned_tx_pieces()

    def serialize(self) -> str:
        """
        Serialize the PSBT as a base 64 encoded string.

        :returns: The base 64 encoded string.
        """
        r = b""

        # magic bytes
        r += b"psbt\xff"

        if self.version == 0:
            # unsigned tx flag
            r += ser_string(ser_compact_size(PSBT.PSBT_GLOBAL_UNSIGNED_TX))

            # write serialized tx
            tx = self.tx.serialize_with_witness()
            r += ser_compact_size(len(tx))
            r += tx

        # write xpubs
        r += SerializeHDKeypath(self.xpub, ser_compact_size(PSBT.PSBT_GLOBAL_XPUB))

        if self.version >= 2:
            assert self.tx_version is not None
            r += ser_string(ser_compact_size(PSBT.PSBT_GLOBAL_TX_VERSION))
            r += ser_string(struct.pack("<I", self.tx_version))

            if self.fallback_locktime is not None:
                r += ser_string(ser_compact_size(PSBT.PSBT_GLOBAL_FALLBACK_LOCKTIME))
                r += ser_string(struct.pack("<I", self.fallback_locktime))

            r += ser_string(ser_compact_size(PSBT.PSBT_GLOBAL_INPUT_COUNT))
            r += ser_string(ser_compact_size(len(self.inputs)))

            r += ser_string(ser_compact_size(PSBT.PSBT_GLOBAL_OUTPUT_COUNT))
            r += ser_string(ser_compact_size(len(self.outputs)))

            if self.tx_modifiable is not None:
                r += ser_string(ser_compact_size(PSBT.PSBT_GLOBAL_TX_MODIFIABLE))
                r += ser_string(struct.pack("<B", self.tx_modifiable))

        if self.version > 0 or self.explicit_version:
            r += ser_string(ser_compact_size(PSBT.PSBT_GLOBAL_VERSION))
            r += ser_string(struct.pack("<I", self.version))

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

    def cache_unsigned_tx_pieces(self) -> None:
        """
        If this PSBT is v0, then the global unsigned transaction will be used to fill in the PSBTv2
        fields so that all users of the PSBT classes can use the same PSBTv2 interface regardless
        of PSBT version.

        Does nothing if the PSBT is already v2.
        """
        # To make things easier, we split up the global transaction
        # and use the PSBTv2 fields for PSBTv0
        if self.tx is not None:
            self.setup_from_tx(self.tx)

    def setup_from_tx(self, tx: CTransaction):
        """
        Fills in the PSBTv2 fields for this PSBT given a transaction

        :param tx: The CTransaction to fill from
        """
        self.tx_version = tx.nVersion
        self.fallback_locktime = tx.nLockTime

        for i, txin in enumerate(tx.vin):
            psbt_in = self.inputs[i]

            psbt_in.prev_txid = ser_uint256(txin.prevout.hash)
            psbt_in.prev_out = txin.prevout.n
            psbt_in.sequence = txin.nSequence

        for i, txout in enumerate(tx.vout):
            psbt_out = self.outputs[i]

            psbt_out.amount = txout.nValue
            psbt_out.script = txout.scriptPubKey

    def compute_lock_time(self) -> int:
        """
        Computes the lock time for this transaction

        :returns: The lock time
        """
        time_lock: Optional[int] = 0
        height_lock: Optional[int] = 0

        for psbt_in in self.inputs:
            if psbt_in.time_locktime is not None and psbt_in.height_locktime is None:
                height_lock = None
                if time_lock is None:
                    raise PSBTSerializationError("Cannot require both time and height locktimes")
            elif psbt_in.time_locktime is None and psbt_in.height_locktime is not None:
                time_lock = None
                if height_lock is None:
                    raise PSBTSerializationError("Cannot require both time and height locktimes")

            if psbt_in.time_locktime is not None and time_lock is not None:
                time_lock = max(time_lock, psbt_in.time_locktime)
            if psbt_in.height_locktime is not None and height_lock is not None:
                height_lock = max(height_lock, psbt_in.height_locktime)

        if height_lock is not None and height_lock > 0:
            return height_lock
        if time_lock is not None and time_lock > 0:
            return time_lock
        if self.fallback_locktime is not None:
            return self.fallback_locktime
        return 0

    def get_unsigned_tx(self) -> CTransaction:
        """
        Get the unsigned transaction represented by this PSBT

        :return: A CTransaction
        """
        if not self.tx.is_null():
            return self.tx

        assert self.tx_version is not None

        tx = CTransaction()
        tx.nVersion = self.tx_version
        self.nLockTime = self.compute_lock_time()

        for psbt_in in self.inputs:
            assert psbt_in.prev_txid is not None
            assert psbt_in.prev_out is not None
            assert psbt_in.sequence is not None

            txin = CTxIn(COutPoint(uint256_from_str(psbt_in.prev_txid), psbt_in.prev_out), b"", psbt_in.sequence)
            tx.vin.append(txin)

        for psbt_out in self.outputs:
            assert psbt_out.amount is not None

            txout = CTxOut(psbt_out.amount, psbt_out.script)
            tx.vout.append(txout)

        tx.rehash()
        return tx

    def _convert_version(self, version) -> None:
        self.version = version
        for psbt_in in self.inputs:
            psbt_in.version = version
        for psbt_out in self.outputs:
            psbt_out.version = version

    def convert_to_v2(self) -> None:
        """
        Sets this PSBT to version 2
        """
        self._convert_version(2)

    def convert_to_v0(self) -> None:
        """
        Sets this PSBT to version 0
        """
        self._convert_version(0)
        self.tx = self.get_unsigned_tx()
        self.explicit_version = False
