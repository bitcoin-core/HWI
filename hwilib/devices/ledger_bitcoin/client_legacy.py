"""
This module provides a compatibility layer between the python client of the Ledger Nano Bitcoin app v2 and the v1.6.5,
by translating client requests to the API of the app v1.6.5.

The bulk of the code is taken from bitcoin-core/HWI, with the necessary adaptations.
https://github.com/bitcoin-core/HWI/tree/a109bcd53d24a52e72f26af3ecbabb64b292ff0c,
"""

import struct
import re
import base64

from .client import Client, TransportClient

from typing import List, Tuple, Optional, Union

from ...common import AddressType, Chain, hash160
from ...key import ExtendedKey, parse_path
from ...psbt import PSBT
from .wallet import WalletPolicy

from ..._script import is_p2sh, is_witness, is_p2wpkh, is_p2wsh

from .btchip.btchip import btchip
from .btchip.btchipUtils import compress_public_key
from .btchip.bitcoinTransaction import bitcoinTransaction


def get_address_type_for_policy(policy: WalletPolicy) -> AddressType:
    if policy.descriptor_template == "pkh(@0/**)":
        return AddressType.LEGACY
    elif policy.descriptor_template == "wpkh(@0/**)":
        return AddressType.WIT
    elif policy.descriptor_template == "sh(wpkh(@0/**))":
        return AddressType.SH_WIT
    else:
        raise ValueError("Invalid or unsupported policy")


class DongleAdaptor:
    # TODO: type for comm_client
    def __init__(self, comm_client) -> None:
        self.comm_client = comm_client

    def exchange(self, apdu: Union[bytes, bytearray]) -> bytearray:
        cla = apdu[0]
        ins = apdu[1]
        p1 = apdu[2]
        p2 = apdu[3]
        lc = apdu[4]
        data = apdu[5:]
        assert len(data) == lc
        return bytearray(self.comm_client.apdu_exchange(cla, ins, data, p1, p2))

class LegacyClient(Client):
    """Wrapper for Ledger Bitcoin app before version 2.0.0."""

    def __init__(self, comm_client: TransportClient, chain: Chain = Chain.MAIN):
        super().__init__(comm_client, chain)

        self.app = btchip(DongleAdaptor(comm_client))

    def get_extended_pubkey(self, path: str, display: bool = False) -> str:
        # mostly taken from HWI

        path = path[2:]
        path = path.replace('h', '\'')
        path = path.replace('H', '\'')

        # This call returns raw uncompressed pubkey, chaincode
        pubkey = self.app.getWalletPublicKey(path, display)
        int_path = parse_path(path)
        if len(path) > 0:
            parent_path = ""
            for ind in path.split("/")[:-1]:
                parent_path += ind + "/"
            parent_path = parent_path[:-1]

            # Get parent key fingerprint
            parent = self.app.getWalletPublicKey(parent_path)
            fpr = hash160(compress_public_key(parent["publicKey"]))[:4]

            child = int_path[-1]
        # Special case for m
        else:
            child = 0
            fpr = b"\x00\x00\x00\x00"

        xpub = ExtendedKey(
            version=ExtendedKey.MAINNET_PUBLIC if self.chain == Chain.MAIN else ExtendedKey.TESTNET_PUBLIC,
            depth=len(path.split("/")) if len(path) > 0 else 0,
            parent_fingerprint=fpr,
            child_num=child,
            chaincode=pubkey["chainCode"],
            privkey=None,
            pubkey=compress_public_key(pubkey["publicKey"]),
        )
        return xpub.to_string()

    def register_wallet(self, wallet: WalletPolicy) -> Tuple[bytes, bytes]:
        raise NotImplementedError # legacy app does not have this functionality

    def get_wallet_address(
        self,
        wallet: WalletPolicy,
        wallet_hmac: Optional[bytes],
        change: int, # Ignored
        address_index: int, # Ignored
        display: bool,
    ) -> str:
        # TODO: check keypath

        if wallet_hmac is not None or wallet.n_keys != 1:
            raise NotImplementedError("Policy wallets are only supported from version 2.0.0. Please update your Ledger hardware wallet")

        if not isinstance(wallet, WalletPolicy):
            raise ValueError("Invalid wallet policy type, it must be WalletPolicy")

        key_info = wallet.keys_info[0]
        try:
            first_slash_pos = key_info.index("/")
            key_origin_end = key_info.index("]")
        except ValueError:
            raise ValueError("Could not extract key origin information")

        if key_info[0] != '[':
            raise ValueError("Key must have key origin information")

        key_origin_path = key_info[first_slash_pos + 1: key_origin_end]

        addr_type = get_address_type_for_policy(wallet)

        p2sh_p2wpkh = addr_type == AddressType.SH_WIT
        bech32 = addr_type == AddressType.WIT
        output = self.app.getWalletPublicKey(key_origin_path, display, p2sh_p2wpkh or bech32, bech32)
        assert isinstance(output["address"], str)
        return output['address'][12:-2] # HACK: A bug in getWalletPublicKey results in the address being returned as the string "bytearray(b'<address>')". This extracts the actual address to work around this.

    # NOTE: This is different from the new API, but we need it for multisig support.
    def sign_psbt(self, psbt: PSBT, wallet: WalletPolicy, wallet_hmac: Optional[bytes]) -> List[Tuple[int, bytes, bytes]]:
        if wallet_hmac is not None or wallet.n_keys != 1:
            raise NotImplementedError("Policy wallets are only supported from version 2.0.0. Please update your Ledger hardware wallet")

        if not isinstance(wallet, WalletPolicy):
            raise ValueError("Invalid wallet policy type, it must be WalletPolicy")

        if wallet.descriptor_template not in ["pkh(@0/**)", "pkh(@0/<0;1>/*)", "wpkh(@0/**)", "wpkh(@0/<0;1>/*)", "sh(wpkh(@0/**))", "sh(wpkh(@0/<0;1>/*))"]:
            raise NotImplementedError("Unsupported policy")

        # the rest of the code is basically the HWI code, and it ignores wallet

        tx = psbt

        c_tx = tx.get_unsigned_tx()
        tx_bytes = c_tx.serialize_with_witness()

        # Master key fingerprint
        master_fpr = hash160(compress_public_key(self.app.getWalletPublicKey('')["publicKey"]))[:4]
        # An entry per input, each with 0 to many keys to sign with
        all_signature_attempts: List[List[Tuple[str, bytes]]] = [[]] * len(c_tx.vin)

        # Get the app version to determine whether to use Trusted Input for segwit
        version = self.app.getFirmwareVersion()
        use_trusted_segwit = (version['major_version'] == 1 and version['minor_version'] >= 4) or version['major_version'] > 1

        # NOTE: We only support signing Segwit inputs, where we can skip over non-segwit
        # inputs, or non-segwit inputs, where *all* inputs are non-segwit. This is due
        # to Ledger's mutually exclusive signing steps for each type.
        segwit_inputs = []
        # Legacy style inputs
        legacy_inputs = []

        has_segwit = False
        has_legacy = False

        script_codes: List[bytes] = [b""] * len(c_tx.vin)

        # Detect changepath, (p2sh-)p2(w)pkh only
        change_path = ''
        for txout, i_num in zip(c_tx.vout, range(len(c_tx.vout))):
            # Find which wallet key could be change based on hdsplit: m/.../1/k
            # Wallets shouldn't be sending to change address as user action
            # otherwise this will get confused
            for pubkey, origin in tx.outputs[i_num].hd_keypaths.items():
                if origin.fingerprint == master_fpr and len(origin.path) > 1 and origin.path[-2] == 1:
                    # For possible matches, check if pubkey matches possible template
                    if hash160(pubkey) in txout.scriptPubKey or hash160(bytearray.fromhex("0014") + hash160(pubkey)) in txout.scriptPubKey:
                        change_path = ''
                        for index in origin.path:
                            change_path += str(index) + "/"
                        change_path = change_path[:-1]

        for txin, psbt_in, i_num in zip(c_tx.vin, tx.inputs, range(len(c_tx.vin))):

            seq_hex = txin.nSequence.to_bytes(4, byteorder="little").hex()

            scriptcode = b""
            utxo = None
            if psbt_in.witness_utxo:
                utxo = psbt_in.witness_utxo
            if psbt_in.non_witness_utxo:
                if txin.prevout.hash != psbt_in.non_witness_utxo.sha256:
                    raise ValueError('Input {} has a non_witness_utxo with the wrong hash'.format(i_num))
                utxo = psbt_in.non_witness_utxo.vout[txin.prevout.n]
            if utxo is None:
                raise Exception("PSBT is missing input utxo information, cannot sign")
            scriptcode = utxo.scriptPubKey

            if is_p2sh(scriptcode):
                if len(psbt_in.redeem_script) == 0:
                    continue
                scriptcode = psbt_in.redeem_script

            is_wit, _, _ = is_witness(scriptcode)

            segwit_inputs.append({"value": txin.prevout.serialize() + struct.pack("<Q", utxo.nValue), "witness": True, "sequence": seq_hex})
            if is_wit:
                if is_p2wsh(scriptcode):
                    if len(psbt_in.witness_script) == 0:
                        continue
                    scriptcode = psbt_in.witness_script
                elif is_p2wpkh(scriptcode):
                    _, _, wit_prog = is_witness(scriptcode)
                    scriptcode = b"\x76\xa9\x14" + wit_prog + b"\x88\xac"
                else:
                    continue
                has_segwit = True
            else:
                # We only need legacy inputs in the case where all inputs are legacy, we check
                # later
                assert psbt_in.non_witness_utxo is not None
                ledger_prevtx = bitcoinTransaction(psbt_in.non_witness_utxo.serialize())
                legacy_inputs.append(self.app.getTrustedInput(ledger_prevtx, txin.prevout.n))
                legacy_inputs[-1]["sequence"] = seq_hex
                has_legacy = True

            if psbt_in.non_witness_utxo and use_trusted_segwit:
                ledger_prevtx = bitcoinTransaction(psbt_in.non_witness_utxo.serialize())
                segwit_inputs[-1].update(self.app.getTrustedInput(ledger_prevtx, txin.prevout.n))

            pubkeys = []
            signature_attempts = []

            # Save scriptcode for later signing
            script_codes[i_num] = scriptcode

            # Find which pubkeys could sign this input (should be all?)
            for pubkey in psbt_in.hd_keypaths.keys():
                if hash160(pubkey) in scriptcode or pubkey in scriptcode:
                    pubkeys.append(pubkey)

            # Figure out which keys in inputs are from our wallet
            for pubkey in pubkeys:
                keypath = psbt_in.hd_keypaths[pubkey]
                if master_fpr == keypath.fingerprint:
                    # Add the keypath strings
                    keypath_str = keypath.get_derivation_path()[2:] # Drop the leading m/
                    signature_attempts.append((keypath_str, pubkey))

            all_signature_attempts[i_num] = signature_attempts

        result: List[int, bytes, bytes] = []

        # Sign any segwit inputs
        if has_segwit:
            # Process them up front with all scriptcodes blank
            blank_script_code = bytearray()
            for i in range(len(segwit_inputs)):
                self.app.startUntrustedTransaction(i == 0, i, segwit_inputs, script_codes[i] if use_trusted_segwit else blank_script_code, c_tx.nVersion)

            # Number of unused fields for Nano S, only changepath and transaction in bytes req
            self.app.finalizeInput(b"DUMMY", -1, -1, change_path, tx_bytes)

            # For each input we control do segwit signature
            for i in range(len(segwit_inputs)):
                for signature_attempt in all_signature_attempts[i]:
                    self.app.startUntrustedTransaction(False, 0, [segwit_inputs[i]], script_codes[i], c_tx.nVersion)

                    result.append((i, signature_attempt[1], self.app.untrustedHashSign(signature_attempt[0], "", c_tx.nLockTime, 0x01)))

        elif has_legacy:
            first_input = True
            # Legacy signing if all inputs are legacy
            for i in range(len(legacy_inputs)):
                for signature_attempt in all_signature_attempts[i]:
                    assert(tx.inputs[i].non_witness_utxo is not None)
                    self.app.startUntrustedTransaction(first_input, i, legacy_inputs, script_codes[i], c_tx.nVersion)
                    self.app.finalizeInput(b"DUMMY", -1, -1, change_path, tx_bytes)

                    result.append((i, signature_attempt[1], self.app.untrustedHashSign(signature_attempt[0], "", c_tx.nLockTime, 0x01)))

                    first_input = False

        # Send list of input signatures
        return result

    def get_master_fingerprint(self) -> bytes:
        master_pubkey = self.app.getWalletPublicKey("")
        return hash160(compress_public_key(master_pubkey["publicKey"]))[:4]

    def sign_message(self, message: Union[str, bytes], keypath: str) -> str:
        if isinstance(message, str):
            message = bytearray(message, 'utf-8')
        else:
            message = bytearray(message)
        keypath = keypath[2:]
        # First display on screen what address you're signing for
        self.app.getWalletPublicKey(keypath, True)
        self.app.signMessagePrepare(keypath, message)
        signature = self.app.signMessageSign()

        # Make signature into standard bitcoin format
        rLength = signature[3]
        r = int.from_bytes(signature[4: 4 + rLength], byteorder="big", signed=True)
        s = int.from_bytes(signature[4 + rLength + 2:], byteorder="big", signed=True)

        sig = bytearray(chr(27 + 4 + (signature[0] & 0x01)), 'utf8') + r.to_bytes(32, byteorder="big", signed=False) + s.to_bytes(32, byteorder="big", signed=False)

        return base64.b64encode(sig).decode('utf-8')
