# Trezor interaction script

from ..hwwclient import HardwareWalletClient
from ..errors import ActionCanceledError, BadArgumentError, DeviceAlreadyInitError, DeviceAlreadyUnlockedError, DeviceConnectionError, DEVICE_NOT_INITIALIZED, DeviceNotReadyError, UnavailableActionError, common_err_msgs, handle_errors
from .trezorlib.client import TrezorClient as Trezor
from .trezorlib.debuglink import TrezorClientDebugLink
from .trezorlib.exceptions import Cancelled
from .trezorlib.transport import enumerate_devices, get_transport, TREZOR_VENDOR_IDS
from .trezorlib.ui import echo, PassphraseUI, mnemonic_words, PIN_CURRENT, PIN_NEW, PIN_CONFIRM, PIN_MATRIX_DESCRIPTION, prompt
from .trezorlib import tools, btc, device
from .trezorlib import messages as proto
from ..base58 import get_xpub_fingerprint, to_address, xpub_main_2_test, get_xpub_fingerprint_hex
from ..serializations import CTxOut, ser_uint256
from .. import bech32
from usb1 import USBErrorNoDevice
from types import MethodType

import base64
import logging
import sys

py_enumerate = enumerate # Need to use the enumerate built-in but there's another function already named that

# Only handles up to 15 of 15
def parse_multisig(script):
    # Get m
    m = script[0] - 80
    if m < 1 or m > 15:
        return (False, None)

    # Get pubkeys and build HDNodePathType
    pubkeys = []
    offset = 1
    while True:
        pubkey_len = script[offset]
        if pubkey_len != 33:
            break
        offset += 1
        key = script[offset:offset + 33]
        offset += 33

        hd_node = proto.HDNodeType(depth=0, fingerprint=0, child_num=0, chain_code=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', public_key=key)
        pubkeys.append(proto.HDNodePathType(node=hd_node, address_n=[]))

    # Check things at the end
    n = script[offset] - 80
    if n != len(pubkeys):
        return (False, None)
    offset += 1
    op_cms = script[offset]
    if op_cms != 174:
        return (False, None)

    # Build MultisigRedeemScriptType and return it
    multisig = proto.MultisigRedeemScriptType(m=m, signatures=[b''] * n, pubkeys=pubkeys)
    return (True, multisig)

def trezor_exception(f):
    def func(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValueError as e:
            raise BadArgumentError(str(e))
        except Cancelled:
            raise ActionCanceledError('{} canceled'.format(f.__name__))
        except USBErrorNoDevice:
            raise DeviceConnectionError('Device disconnected')
    return func

def interactive_get_pin(self, code=None):
    if code == PIN_CURRENT:
        desc = "current PIN"
    elif code == PIN_NEW:
        desc = "new PIN"
    elif code == PIN_CONFIRM:
        desc = "new PIN again"
    else:
        desc = "PIN"

    echo(PIN_MATRIX_DESCRIPTION)

    while True:
        pin = prompt("Please enter {}".format(desc), hide_input=True)
        if not pin.isdigit():
            echo("Non-numerical PIN provided, please try again")
        else:
            return pin

# This class extends the HardwareWalletClient for Trezor specific things
class TrezorClient(HardwareWalletClient):

    def __init__(self, path, password=''):
        super(TrezorClient, self).__init__(path, password)
        self.simulator = False
        if path.startswith('udp'):
            logging.debug('Simulator found, using DebugLink')
            transport = get_transport(path)
            self.client = TrezorClientDebugLink(transport=transport)
            self.simulator = True
            self.client.set_passphrase(password)
        else:
            self.client = Trezor(transport=get_transport(path), ui=PassphraseUI(password))

        # if it wasn't able to find a client, throw an error
        if not self.client:
            raise IOError("no Device")

        self.password = password
        self.type = 'Trezor'

    def _check_unlocked(self):
        self.client.init_device()
        if self.client.features.pin_protection and not self.client.features.pin_cached:
            raise DeviceNotReadyError('{} is locked. Unlock by using \'promptpin\' and then \'sendpin\'.'.format(self.type))

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    @trezor_exception
    def get_pubkey_at_path(self, path):
        self._check_unlocked()
        try:
            expanded_path = tools.parse_path(path)
        except ValueError as e:
            raise BadArgumentError(str(e))
        output = btc.get_public_node(self.client, expanded_path)
        if self.is_testnet:
            return {'xpub': xpub_main_2_test(output.xpub)}
        else:
            return {'xpub': output.xpub}

    # Must return a hex string with the signed transaction
    # The tx must be in the psbt format
    @trezor_exception
    def sign_tx(self, tx):
        self._check_unlocked()

        # Get this devices master key fingerprint
        master_key = btc.get_public_node(self.client, [0])
        master_fp = get_xpub_fingerprint(master_key.xpub)

        # Do multiple passes for multisig
        passes = 1
        p = 0

        while p < passes:
            # Prepare inputs
            inputs = []
            to_ignore = [] # Note down which inputs whose signatures we're going to ignore
            for input_num, (psbt_in, txin) in py_enumerate(list(zip(tx.inputs, tx.tx.vin))):
                txinputtype = proto.TxInputType()

                # Set the input stuff
                txinputtype.prev_hash = ser_uint256(txin.prevout.hash)[::-1]
                txinputtype.prev_index = txin.prevout.n
                txinputtype.sequence = txin.nSequence

                # Detrermine spend type
                scriptcode = b''
                if psbt_in.non_witness_utxo:
                    utxo = psbt_in.non_witness_utxo.vout[txin.prevout.n]
                    txinputtype.script_type = proto.InputScriptType.SPENDADDRESS
                    scriptcode = utxo.scriptPubKey
                    txinputtype.amount = psbt_in.non_witness_utxo.vout[txin.prevout.n].nValue
                elif psbt_in.witness_utxo:
                    utxo = psbt_in.witness_utxo
                    # Check if the output is p2sh
                    if psbt_in.witness_utxo.is_p2sh():
                        txinputtype.script_type = proto.InputScriptType.SPENDP2SHWITNESS
                    else:
                        txinputtype.script_type = proto.InputScriptType.SPENDWITNESS
                    scriptcode = psbt_in.witness_utxo.scriptPubKey
                    txinputtype.amount = psbt_in.witness_utxo.nValue

                # Set the script
                if psbt_in.witness_script:
                    scriptcode = psbt_in.witness_script
                elif psbt_in.redeem_script:
                    scriptcode = psbt_in.redeem_script

                def ignore_input():
                    txinputtype.address_n = [0x80000000]
                    txinputtype.multisig = None
                    txinputtype.script_type = proto.InputScriptType.SPENDWITNESS
                    inputs.append(txinputtype)
                    to_ignore.append(input_num)

                # Check for multisig
                is_ms, multisig = parse_multisig(scriptcode)
                if is_ms:
                    # Add to txinputtype
                    txinputtype.multisig = multisig
                    if psbt_in.non_witness_utxo:
                        if utxo.is_p2sh:
                            txinputtype.script_type = proto.InputScriptType.SPENDMULTISIG
                        else:
                            # Cannot sign bare multisig, ignore it
                            ignore_input()
                            continue
                elif not is_ms and psbt_in.non_witness_utxo and not utxo.is_p2pkh:
                    # Cannot sign unknown spk, ignore it
                    ignore_input()
                    continue
                elif not is_ms and psbt_in.witness_utxo and psbt_in.witness_script:
                    # Cannot sign unknown witness script, ignore it
                    ignore_input()
                    continue

                # Find key to sign with
                found = False
                our_keys = 0
                for key in psbt_in.hd_keypaths.keys():
                    keypath = psbt_in.hd_keypaths[key]
                    if keypath[0] == master_fp and key not in psbt_in.partial_sigs:
                        if not found:
                            txinputtype.address_n = keypath[1:]
                            found = True
                        our_keys += 1

                # Determine if we need to do more passes to sign everything
                if our_keys > passes:
                    passes = our_keys

                if not found:
                    # This input is not one of ours
                    ignore_input()
                    continue

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
            for i, out in py_enumerate(tx.tx.vout):
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
                        raise BadArgumentError("Output is not an address")

                # Add the derivation path for change, but only if there is exactly one derivation path
                psbt_out = tx.outputs[i]
                if len(psbt_out.hd_keypaths) == 1:
                    _, keypath = next(iter(psbt_out.hd_keypaths.items()))
                    if keypath[0] == master_fp:
                        wit, ver, prog = out.is_witness()
                        if out.is_p2pkh():
                            txoutput.address_n = keypath[1:]
                            txoutput.address = None
                        elif wit:
                            txoutput.script_type = proto.OutputScriptType.PAYTOWITNESS
                            txoutput.address_n = keypath[1:]
                            txoutput.address = None
                        elif out.is_p2sh() and psbt_out.redeem_script:
                            wit, ver, prog = CTxOut(0, psbt_out.redeem_script).is_witness()
                            if wit and len(prog) == 20:
                                txoutput.script_type = proto.OutputScriptType.PAYTOP2SHWITNESS
                                txoutput.address_n = keypath[1:]
                                txoutput.address = None

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

            # Each input has one signature
            for input_num, (psbt_in, sig) in py_enumerate(list(zip(tx.inputs, signed_tx[0]))):
                if input_num in to_ignore:
                    continue
                for pubkey in psbt_in.hd_keypaths.keys():
                    fp = psbt_in.hd_keypaths[pubkey][0]
                    if fp == master_fp and pubkey not in psbt_in.partial_sigs:
                        psbt_in.partial_sigs[pubkey] = sig + b'\x01'
                        break

            p += 1

        return {'psbt': tx.serialize()}

    # Must return a base64 encoded string with the signed message
    # The message can be any string
    @trezor_exception
    def sign_message(self, message, keypath):
        self._check_unlocked()
        path = tools.parse_path(keypath)
        result = btc.sign_message(self.client, 'Bitcoin', path, message)
        return {'signature': base64.b64encode(result.signature).decode('utf-8')}

    # Display address of specified type on the device. Only supports single-key based addresses.
    @trezor_exception
    def display_address(self, keypath, p2sh_p2wpkh, bech32, redeem_script=''):
        self._check_unlocked()
        # redeem_script means p2sh/multisig
        if redeem_script:
            expanded_path = tools.parse_path(keypath)

            # Get multisig object required by Trezor's get_address
            multisig = parse_multisig(bytes.fromhex(redeem_script))
            assert multisig[0]
            multisig = multisig[1]

            # Script type
            if p2sh_p2wpkh:
                script_type = proto.InputScriptType.SPENDP2SHWITNESS
            elif bech32:
                script_type = proto.InputScriptType.SPENDWITNESS
            else:
                script_type = proto.InputScriptType.SPENDMULTISIG

            address = btc.get_address(
                self.client,
                'Testnet' if self.is_testnet else 'Bitcoin',
                expanded_path,
                show_display=True,
                script_type=script_type,
                multisig=multisig,
            )
        # single-sig
        else:
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
    @trezor_exception
    def setup_device(self, label='', passphrase=''):
        self.client.init_device()
        if not self.simulator:
            # Use interactive_get_pin
            self.client.ui.get_pin = MethodType(interactive_get_pin, self.client.ui)

        if self.client.features.initialized:
            raise DeviceAlreadyInitError('Device is already initialized. Use wipe first and try again')
        device.reset(self.client, passphrase_protection=bool(self.password))
        return {'success': True}

    # Wipe this device
    @trezor_exception
    def wipe_device(self):
        self._check_unlocked()
        device.wipe(self.client)
        return {'success': True}

    # Restore device from mnemonic or xprv
    @trezor_exception
    def restore_device(self, label=''):
        self.client.init_device()
        if not self.simulator:
            # Use interactive_get_pin
            self.client.ui.get_pin = MethodType(interactive_get_pin, self.client.ui)

        device.recover(self.client, label=label, input_callback=mnemonic_words(), passphrase_protection=bool(self.password))
        return {'success': True}

    # Begin backup process
    def backup_device(self, label='', passphrase=''):
        raise UnavailableActionError('The {} does not support creating a backup via software'.format(self.type))

    # Close the device
    @trezor_exception
    def close(self):
        self.client.close()

    # Prompt for a pin on device
    @trezor_exception
    def prompt_pin(self):
        self.client.open()
        self.client.init_device()
        if not self.client.features.pin_protection:
            raise DeviceAlreadyUnlockedError('This device does not need a PIN')
        if self.client.features.pin_cached:
            raise DeviceAlreadyUnlockedError('The PIN has already been sent to this device')
        print('Use \'sendpin\' to provide the number positions for the PIN as displayed on your device\'s screen', file=sys.stderr)
        print(PIN_MATRIX_DESCRIPTION, file=sys.stderr)
        self.client.call_raw(proto.Ping(message=b'ping', button_protection=False, pin_protection=True, passphrase_protection=False))
        return {'success': True}

    # Send the pin
    @trezor_exception
    def send_pin(self, pin):
        self.client.open()
        if not pin.isdigit():
            raise BadArgumentError("Non-numeric PIN provided")
        resp = self.client.call_raw(proto.PinMatrixAck(pin=pin))
        if isinstance(resp, proto.Failure):
            self.client.features = self.client.call_raw(proto.GetFeatures())
            if isinstance(self.client.features, proto.Features):
                if not self.client.features.pin_protection:
                    raise DeviceAlreadyUnlockedError('This device does not need a PIN')
                if self.client.features.pin_cached:
                    raise DeviceAlreadyUnlockedError('The PIN has already been sent to this device')
            return {'success': False}
        return {'success': True}

def enumerate(password=''):
    results = []
    for dev in enumerate_devices():
        # enumerate_devices filters to Trezors and Keepkeys.
        # Only allow Trezors and unknowns. Unknown devices will reach the check for vendor later
        if dev.get_usb_vendor_id() not in TREZOR_VENDOR_IDS | {-1}:
            continue
        d_data = {}

        d_data['type'] = 'trezor'
        d_data['path'] = dev.get_path()

        client = None
        with handle_errors(common_err_msgs["enumerate"], d_data):
            client = TrezorClient(d_data['path'], password)
            client.client.init_device()
            if 'trezor' not in client.client.features.vendor:
                continue

            d_data['model'] = 'trezor_' + client.client.features.model.lower()
            if d_data['path'] == 'udp:127.0.0.1:21324':
                d_data['model'] += '_simulator'

            d_data['needs_pin_sent'] = client.client.features.pin_protection and not client.client.features.pin_cached
            if client.client.features.model == '1':
                d_data['needs_passphrase_sent'] = client.client.features.passphrase_protection # always need the passphrase sent for Trezor One if it has passphrase protection enabled
            else:
                d_data['needs_passphrase_sent'] = client.client.features.passphrase_protection and not client.client.features.passphrase_cached
            if d_data['needs_pin_sent']:
                raise DeviceNotReadyError('Trezor is locked. Unlock by using \'promptpin\' and then \'sendpin\'.')
            if d_data['needs_passphrase_sent'] and not password:
                raise DeviceNotReadyError("Passphrase needs to be specified before the fingerprint information can be retrieved")
            if client.client.features.initialized:
                master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
                d_data['fingerprint'] = get_xpub_fingerprint_hex(master_xpub)
                d_data['needs_passphrase_sent'] = False # Passphrase is always needed for the above to have worked, so it's already sent
            else:
                d_data['error'] = 'Not initialized'
                d_data['code'] = DEVICE_NOT_INITIALIZED

        if client:
            client.close()

        results.append(d_data)
    return results
