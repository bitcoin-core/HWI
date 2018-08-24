# KeepKey interaction script

from hwi import HardwareWalletClient
from keepkeylib.transport_hid import HidTransport
from keepkeylib.client import KeepKeyClient as KeepKey
from keepkeylib import tools
from keepkeylib import messages_pb2, types_pb2 as proto
from keepkeylib.tx_api import TxApi
from base58 import get_xpub_fingerprint, decode, to_address, xpub_main_2_test
from serializations import ser_uint256, uint256_from_str

import binascii
import json

class TxAPIPSBT(TxApi):

    def __init__(self, psbt):
        super().__init__('bitcoin_psbt', None)
        self.psbt = psbt

    def get_tx(self, txhash):
        tx = None
        for psbt_in in self.psbt.inputs:
            if psbt_in.non_witness_utxo and psbt_in.non_witness_utxo.sha256 == uint256_from_str(binascii.unhexlify(txhash)[::-1]):
                tx = psbt_in.non_witness_utxo
        if not tx:
            raise ValueError("TX {} not found in PSBT".format(txhash))

        t = proto.TransactionType()
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

        return t

# This class extends the HardwareWalletClient for Digital Bitbox specific things
class KeepKeyClient(HardwareWalletClient):

    # device is an HID device that has already been opened.
    def __init__(self, device, path):
        super(KeepKeyClient, self).__init__(device)
        device.close()
        devices = HidTransport.enumerate()
        self.client = None
        for d in devices:
            if d[0] == path:
                transport = HidTransport(d)
                self.client = KeepKey(transport)
                break

        # if it wasn't able to find a client, throw an error
        if not self.client:
            raise IOError("no Device")

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        path = path.replace('h', '\'')
        path = path.replace('H', '\'')
        expanded_path = self.client.expand_path(path)
        output = self.client.get_public_node(expanded_path)
        if self.is_testnet:
            return json.dumps({'xpub':xpub_main_2_test(output.xpub)})
        else:
            return json.dumps({'xpub':output.xpub})

    # Must return a hex string with the signed transaction
    # The tx must be in the combined unsigned transaction format
    def sign_tx(self, tx):

        # Get this devices master key fingerprint
        master_key = self.client.get_public_node([0])
        master_fp = get_xpub_fingerprint(master_key.xpub)

        # Prepare inputs
        inputs = []
        for psbt_in, txin in zip(tx.inputs, tx.tx.vin):
            txinputtype = proto.TxInputType()

            # Set the input stuff
            txinputtype.prev_hash = ser_uint256(txin.prevout.hash)[::-1]
            txinputtype.prev_index = txin.prevout.n
            txinputtype.sequence = txin.nSequence

            # Check for 1 key
            if len(psbt_in.hd_keypaths) == 1:
                # Is this key ours
                pubkey = list(psbt_in.hd_keypaths.keys())[0]
                fp = psbt_in.hd_keypaths[pubkey][0]
                keypath = psbt_in.hd_keypaths[pubkey][1:]
                if fp == master_fp:
                    # Set the keypath
                    txinputtype.address_n.extend(keypath)
                    if psbt_in.non_witness_utxo:
                        txinputtype.script_type = 0
                    elif psbt_in.witness_utxo:
                        # Check if the output is p2sh
                        if psbt_in.witness_utxo.is_p2sh():
                            txinputtype.script_type = 3
                        else:
                            txinputtype.script_type = 4
                else:
                    raise TypeError("All inputs must have a key for this device")

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
        else:
            p2pkh_version = b'\x00'
            p2sh_version = b'\x05'

        # prepare outputs
        outputs = []
        for out in tx.tx.vout:
            txoutput = proto.TxOutputType()
            txoutput.amount = out.nValue
            if out.is_p2pkh():
                txoutput.address = to_address(out.scriptPubKey[3:23], p2pkh_version)
                txoutput.script_type = 0
            elif out.is_p2sh():
                txoutput.address = to_address(out.scriptPubKey[2:22], p2sh_version)
                txoutput.script_type = 1
            else:
                # TODO: Figure out what to do here. for now, just break
                break

            # append to outputs
            outputs.append(txoutput)
            print(txoutput)

        # Sign the transaction
        self.client.set_tx_api(TxAPIPSBT(tx))
        if self.is_testnet:
            signed_tx = self.client.sign_tx("Testnet", inputs, outputs, tx.tx.nVersion, tx.tx.nLockTime)
        else:
            signed_tx = self.client.sign_tx("Bitcoin", inputs, outputs, tx.tx.nVersion, tx.tx.nLockTime)

        signatures = signed_tx[0]
        print(binascii.hexlify(signed_tx[1]))
        for psbt_in in tx.inputs:
            for pubkey, sig in zip(psbt_in.hd_keypaths.keys(), signatures):
                fp = psbt_in.hd_keypaths[pubkey][0]
                keypath = psbt_in.hd_keypaths[pubkey][1:]
                if fp == master_fp:
                    psbt_in.partial_sigs[pubkey] = sig + b'\x01'

        return tx.serialize()

    # Must return a base64 encoded string with the signed message
    # The message can be any string
    def sign_message(self, message):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

    # Setup a new device
    def setup_device(self):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

    # Wipe this device
    def wipe_device(self):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')
