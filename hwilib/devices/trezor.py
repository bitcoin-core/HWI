# Trezor interaction script

from ..hwwclient import HardwareWalletClient, DeviceAlreadyInitError, UnavailableActionError
from trezorlib.client import TrezorClient as Trezor
from trezorlib.debuglink import TrezorClientDebugLink
from trezorlib.transport import enumerate_devices, get_transport
from trezorlib.ui import ClickUI, mnemonic_words
from trezorlib import protobuf, tools, btc, device
from trezorlib import messages as proto
from ..base58 import get_xpub_fingerprint, decode, to_address, xpub_main_2_test, get_xpub_fingerprint_hex
from ..serializations import ser_uint256, uint256_from_str
from .. import bech32

import binascii
import json
import logging
import os

# This class extends the HardwareWalletClient for Trezor specific things
class TrezorClient(HardwareWalletClient):

    def __init__(self, path, password=''):
        super(TrezorClient, self).__init__(path, password)
        if path.startswith('udp'):
            logging.debug('Simulator found, using DebugLink')
            transport = get_transport(path)
            self.client = TrezorClientDebugLink(transport=transport)
        else:
            self.client = Trezor(transport=get_transport(path), ui=ClickUI())

        # if it wasn't able to find a client, throw an error
        if not self.client:
            raise IOError("no Device")

        self.password = password
        os.environ['PASSPHRASE'] = password

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        expanded_path = tools.parse_path(path)
        output = btc.get_public_node(self.client, expanded_path)
        if self.is_testnet:
            return {'xpub':xpub_main_2_test(output.xpub)}
        else:
            return {'xpub':output.xpub}

    # Must return a hex string with the signed transaction
    # The tx must be in the psbt format
    def sign_tx(self, tx):

        # Get this devices master key fingerprint
        master_key = btc.get_public_node(self.client, [0])
        master_fp = get_xpub_fingerprint(master_key.xpub)

        # Prepare inputs
        inputs = []
        for psbt_in, txin in zip(tx.inputs, tx.tx.vin):
            txinputtype = proto.TxInputType()

            # Set the input stuff
            txinputtype.prev_hash = ser_uint256(txin.prevout.hash)[::-1]
            txinputtype.prev_index = txin.prevout.n
            txinputtype.sequence = txin.nSequence

            # Detrermine spend type
            if psbt_in.non_witness_utxo:
                txinputtype.script_type = proto.InputScriptType.SPENDADDRESS
            elif psbt_in.witness_utxo:
                # Check if the output is p2sh
                if psbt_in.witness_utxo.is_p2sh():
                    txinputtype.script_type = proto.InputScriptType.SPENDP2SHWITNESS
                else:
                    txinputtype.script_type = proto.InputScriptType.SPENDWITNESS

            # Check for 1 key
            if len(psbt_in.hd_keypaths) == 1:
                # Is this key ours
                pubkey = list(psbt_in.hd_keypaths.keys())[0]
                fp = psbt_in.hd_keypaths[pubkey][0]
                keypath = list(psbt_in.hd_keypaths[pubkey][1:])
                if fp == master_fp:
                    # Set the keypath
                    txinputtype.address_n = keypath

            # Check for multisig (more than 1 key)
            elif len(psbt_in.hd_keypaths) > 1:
                raise TypeError("Cannot sign multisig yet")
            else:
                raise TypeError("All inputs must have a key for this device")

            # Set the amount
            if psbt_in.non_witness_utxo:
                txinputtype.amount = psbt_in.non_witness_utxo.vout[txin.prevout.n].nValue
            elif psbt_in.witness_utxo:
                txinputtype.amount = psbt_in.witness_utxo.nValue

            # append to inputs
            inputs.append(txinputtype)

        # address version byte
        if self.is_testnet:
            p2pkh_version = b'\x6f'
            p2sh_version = b'\xc4'
            bech32_hrp = 'tb'
        else:
            p2pkh_version = b'\x00'
            p2sh_version = b'\x05'
            bech32_hrp = 'bc'

        # prepare outputs
        outputs = []
        for out in tx.tx.vout:
            txoutput = proto.TxOutputType()
            txoutput.amount = out.nValue
            txoutput.script_type = proto.OutputScriptType.PAYTOADDRESS
            if out.is_p2pkh():
                txoutput.address = to_address(out.scriptPubKey[3:23], p2pkh_version)
            elif out.is_p2sh():
                txoutput.address = to_address(out.scriptPubKey[2:22], p2sh_version)
            else:
                wit, ver, prog = out.is_witness()
                if wit:
                    txoutput.address = bech32.encode(bech32_hrp, ver, prog)
                else:
                    raise TypeError("Output is not an address")

            # append to outputs
            outputs.append(txoutput)

        # Prepare prev txs
        prevtxs = {}
        for psbt_in in tx.inputs:
            if psbt_in.non_witness_utxo:
                prev = psbt_in.non_witness_utxo

                t = proto.TransactionType()
                t.version = prev.nVersion
                t.lock_time = prev.nLockTime

                for vin in prev.vin:
                    i = proto.TxInputType()
                    i.prev_hash = ser_uint256(vin.prevout.hash)[::-1]
                    i.prev_index = vin.prevout.n
                    i.script_sig = vin.scriptSig
                    i.sequence = vin.nSequence
                    t.inputs.append(i)

                for vout in prev.vout:
                    o = proto.TxOutputBinType()
                    o.amount = vout.nValue
                    o.script_pubkey = vout.scriptPubKey
                    t.bin_outputs.append(o)
                logging.debug(psbt_in.non_witness_utxo.hash)
                prevtxs[ser_uint256(psbt_in.non_witness_utxo.sha256)[::-1]] = t

        # Sign the transaction
        tx_details = proto.SignTx()
        tx_details.version = tx.tx.nVersion
        tx_details.lock_time = tx.tx.nLockTime
        if self.is_testnet:
            signed_tx = btc.sign_tx(self.client, "Testnet", inputs, outputs, tx_details, prevtxs)
        else:
            signed_tx = btc.sign_tx(self.client, "Bitcoin", inputs, outputs, tx_details, prevtxs)

        signatures = signed_tx[0]
        for psbt_in in tx.inputs:
            for pubkey, sig in zip(psbt_in.hd_keypaths.keys(), signatures):
                fp = psbt_in.hd_keypaths[pubkey][0]
                keypath = psbt_in.hd_keypaths[pubkey][1:]
                if fp == master_fp:
                    psbt_in.partial_sigs[pubkey] = sig + b'\x01'
                break
            signatures.remove(sig)

        return {'psbt':tx.serialize()}

    # Must return a base64 encoded string with the signed message
    # The message can be any string
    def sign_message(self, message, keypath):
        raise NotImplementedError('The Trezor does not currently implement signmessage')

    # Display address of specified type on the device. Only supports single-key based addresses.
    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        expanded_path = tools.parse_path(keypath)
        address = btc.get_address(
            self.client,
            "Testnet" if self.is_testnet else "Bitcoin",
            expanded_path,
            show_display=True,
            script_type=proto.InputScriptType.SPENDWITNESS if bech32 else (proto.InputScriptType.SPENDP2SHWITNESS if p2sh_p2wpkh else proto.InputScriptType.SPENDADDRESS)
        )
        return {'address': address}

    # Setup a new device
    def setup_device(self, label='', passphrase=''):
        if self.client.features.initialized:
            raise DeviceAlreadyInitError('Device is already initialized. Use wipe first and try again')
        passphrase_enabled = False
        if self.password:
            passphrase_enabled = True
        device.reset(self.client, passphrase_protection=bool(self.password))
        return {'success': True}

    # Wipe this device
    def wipe_device(self):
        device.wipe(self.client)
        return {'success': True}

    # Restore device from mnemonic or xprv
    def restore_device(self, label=''):
        passphrase_enabled = False
        device.recover(self.client, label=label, input_callback=mnemonic_words, passphrase_protection=bool(self.password))
        return {'success': True}

    # Begin backup process
    def backup_device(self, label='', passphrase=''):
        raise UnavailableActionError('The Trezor does not support creating a backup via software')

    # Close the device
    def close(self):
        self.client.close()

def enumerate(password=''):
    results = []
    for dev in enumerate_devices():
        d_data = {}

        d_data['type'] = 'trezor'
        d_data['path'] = dev.get_path()

        try:
            client = TrezorClient(d_data['path'], password)
            if client.client.features.initialized:
                master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
                d_data['fingerprint'] = get_xpub_fingerprint_hex(master_xpub)
            else:
                d_data['error'] = 'Not initialized'
            client.close()
        except Exception as e:
            d_data['error'] = "Could not open client or get fingerprint information: " + str(e)

        results.append(d_data)
    return results
