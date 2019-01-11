# KeepKey interaction script

from ..hwwclient import HardwareWalletClient, UnavailableActionError
from keepkeylib.transport_hid import HidTransport
from keepkeylib.transport_udp import UDPTransport
from keepkeylib.client import KeepKeyClient as KeepKey
from keepkeylib.client import KeepKeyDebugClient as KeepKeyDebug
from keepkeylib import tools
from keepkeylib import messages_pb2, types_pb2 as proto
from keepkeylib.tx_api import TxApi
from ..base58 import get_xpub_fingerprint, decode, to_address, xpub_main_2_test, get_xpub_fingerprint_hex
from ..serializations import ser_uint256, uint256_from_str
from .. import bech32

import base64
import binascii
import json
import os

KEEPKEY_VENDOR_ID = 0x2B24
KEEPKEY_DEVICE_ID = 0x0001

py_enumerate = enumerate # Need to use the enumerate built-in but there's another function already named that

class TxAPIPSBT(TxApi):

    def __init__(self, psbt):
        super().__init__('bitcoin_psbt', None)
        self.psbt = psbt

    def get_tx(self, txhash):
        # Find index of the input
        for i, input in py_enumerate(self.psbt.tx.vin):
            if input.prevout.hash == uint256_from_str(binascii.unhexlify(txhash)[::-1]):
                break

        psbt_in = self.psbt.inputs[i]
        t = proto.TransactionType()
        if psbt_in.non_witness_utxo:
            assert(psbt_in.non_witness_utxo.sha256 == uint256_from_str(binascii.unhexlify(txhash)[::-1]))
            tx = psbt_in.non_witness_utxo

            t.version = tx.nVersion
            t.lock_time = tx.nLockTime

            for vin in tx.vin:
                i = t.inputs.add()
                i.prev_hash = ser_uint256(vin.prevout.hash)[::-1]
                i.prev_index = vin.prevout.n
                i.script_sig = vin.scriptSig
                i.sequence = vin.nSequence

            for vout in tx.vout:
                o = t.bin_outputs.add()
                o.amount = vout.nValue
                o.script_pubkey = vout.scriptPubKey
        elif psbt_in.witness_utxo:
            # HACK: the library looks up this info for all inputs. we just need to appease it for segwit stuff
            t.version = 1
            t.lock_time = 0
            o = t.bin_outputs.add()
            o.amount = psbt_in.witness_utxo.nValue
            o.script_pubkey = psbt_in.witness_utxo.scriptPubKey
        else:
            raise ValueError('{} is not an input in this transaction'.format(txhash))

        return t

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

# This class extends the HardwareWalletClient for Digital Bitbox specific things
class KeepkeyClient(HardwareWalletClient):

    def __init__(self, path, password=''):
        super(KeepkeyClient, self).__init__(path, password)
        if path.startswith('hid:'):
            path = path[4:]
            transport = HidTransport((path.encode(), None))
            self.client = KeepKey(transport)
        elif path.startswith('udp:'):
            path = path[4:]
            transport = UDPTransport(path)
            # Use the debug client for the simulator
            self.client = KeepKeyDebug(transport)
            # Get the debug link
            ip, port = path.split(':')
            new_port = int(port) + 1
            debug_transport = UDPTransport('{}:{}'.format(ip, new_port))
            self.client.set_debuglink(debug_transport)
        else:
            raise IOError('Unknown device transport')

        # if it wasn't able to find a client, throw an error
        if not self.client:
            raise IOError("no Device")

        self.password = password
        os.environ['PASSPHRASE'] = password

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        path = path.replace('h', '\'')
        path = path.replace('H', '\'')
        expanded_path = tools.parse_path(path)
        output = self.client.get_public_node(expanded_path)
        if self.is_testnet:
            return {'xpub':xpub_main_2_test(output.xpub)}
        else:
            return {'xpub':output.xpub}

    # Must return a hex string with the signed transaction
    # The tx must be in the combined unsigned transaction format
    def sign_tx(self, tx):

        # Get this devices master key fingerprint
        master_key = self.client.get_public_node([0])
        master_fp = get_xpub_fingerprint(master_key.xpub)

        # Do multiple passes for multisig
        passes = 1
        p = 0

        while p < passes:
            # Prepare inputs
            inputs = []
            to_ignore = []
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
                    txinputtype.script_type = proto.SPENDADDRESS
                    scriptcode = utxo.scriptPubKey
                    txinputtype.amount = psbt_in.non_witness_utxo.vout[txin.prevout.n].nValue
                elif psbt_in.witness_utxo:
                    utxo = psbt_in.witness_utxo
                    # Check if the output is p2sh
                    if psbt_in.witness_utxo.is_p2sh():
                        txinputtype.script_type = proto.SPENDP2SHWITNESS
                    else:
                        txinputtype.script_type = proto.SPENDWITNESS
                    scriptcode = psbt_in.witness_utxo.scriptPubKey
                    txinputtype.amount = psbt_in.witness_utxo.nValue

                # Set the script
                if psbt_in.witness_script:
                    scriptcode = psbt_in.witness_script
                elif psbt_in.redeem_script:
                    scriptcode = psbt_in.redeem_script

                def ignore_input():
                    txinputtype.address_n.extend([0x80000000])
                    txinputtype.ClearField('multisig')
                    txinputtype.script_type = proto.SPENDWITNESS
                    inputs.append(txinputtype)
                    to_ignore.append(input_num)

                # Check for multisig
                is_ms, multisig = parse_multisig(scriptcode)
                if is_ms:
                    # Add to txinputtype
                    txinputtype.multisig.CopyFrom(multisig)
                    if psbt_in.non_witness_utxo:
                        if utxo.is_p2sh:
                            txinputtype.script_type = proto.SPENDMULTISIG
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
                            txinputtype.address_n.extend(keypath[1:])
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
            for out in tx.tx.vout:
                txoutput = proto.TxOutputType()
                txoutput.amount = out.nValue
                txoutput.script_type = proto.PAYTOADDRESS
                if out.is_p2pkh():
                    txoutput.address = to_address(out.scriptPubKey[3:23], p2pkh_version)
                    txoutput.script_type = 0
                elif out.is_p2sh():
                    txoutput.address = to_address(out.scriptPubKey[2:22], p2sh_version)
                    txoutput.script_type = 1
                else:
                    wit, ver, prog = out.is_witness()
                    if wit:
                        txoutput.address = bech32.encode(bech32_hrp, ver, prog)
                    else:
                        raise TypeError("Output is not an address")

                # append to outputs
                outputs.append(txoutput)

            # Sign the transaction
            self.client.set_tx_api(TxAPIPSBT(tx))
            if self.is_testnet:
                signed_tx = self.client.sign_tx("Testnet", inputs, outputs, tx.tx.nVersion, tx.tx.nLockTime)
            else:
                signed_tx = self.client.sign_tx("Bitcoin", inputs, outputs, tx.tx.nVersion, tx.tx.nLockTime)

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

        return {'psbt':tx.serialize()}

    # Must return a base64 encoded string with the signed message
    # The message can be any string
    def sign_message(self, message, keypath):
        keypath = keypath.replace('h', '\'')
        keypath = keypath.replace('H', '\'')
        expanded_path = tools.parse_path(keypath)
        result = self.client.sign_message('Bitcoin', expanded_path, message)
        return {'signature': base64.b64encode(result.signature).decode('utf-8')}

    # Display address of specified type on the device. Only supports single-key based addresses.
    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        keypath = keypath.replace('h', '\'')
        keypath = keypath.replace('H', '\'')
        expanded_path = tools.parse_path(keypath)
        address = self.client.get_address(
            "Testnet" if self.is_testnet else "Bitcoin",
            expanded_path,
            show_display=True,
            script_type=proto.SPENDWITNESS if bech32 else (proto.SPENDP2SHWITNESS if p2sh_p2wpkh else proto.SPENDADDRESS)
        )
        return {'address': address}

    # Setup a new device
    def setup_device(self, label='', passphrase=''):
        if self.client.features.initialized:
            raise DeviceAlreadyInitError('Device is already initialized. Use wipe first and try again')
        self.client.reset_device(False, 256, bool(self.password), True, label, 'english')
        return {'success': True}

    # Wipe this device
    def wipe_device(self):
        self.client.wipe_device()
        return {'success': True}

    # Restore device from mnemonic or xprv
    def restore_device(self, label=''):
        self.client.recovery_device(False, 24, bool(self.password), True, label, 'english')
        return {'success': True}

    # Begin backup process
    def backup_device(self, label='', passphrase=''):
        raise UnavailableActionError('The Keepkey does not support creating a backup via software')

    # Close the device
    def close(self):
        self.client.close()

def enumerate(password=''):
    results = []
    paths = []
    for d in HidTransport.enumerate():
        paths.append('hid:{}'.format(d[0].decode()))

    # Try to open the simulator device and conenct to it
    try:
        sim_dev = UDPTransport('127.0.0.1:21324')
        sim_dev.socket.sendall(b"PINGPING")
        resp = sim_dev.socket.recv(8)
        if resp != b'PONGPONG':
            pass
        paths.append('udp:127.0.0.1:21324')
    except:
        pass

    for path in paths:
        d_data = {}

        d_data['type'] = 'keepkey'
        d_data['path'] = path

        try:
            client = KeepkeyClient(path, password)
            if client.client.features.initialized:
                master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
                d_data['fingerprint'] = get_xpub_fingerprint_hex(master_xpub)
            else:
                d_data['error'] = 'Not initialized'
            client.close()
        except Exception as e:
            if str(e) == 'Unsupported device':
                continue
            d_data['error'] = "Could not open client or get fingerprint information: " + str(e)

        results.append(d_data)
    return results
