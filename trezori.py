# Trezor interaction script

from hwi import HardwareWalletClient
from trezorlib.transport_hid import HidTransport
from trezorlib.client import TrezorClient as Trezor
from trezorlib.types_trezor_pb2 import TxInputType, TxOutputType, TransactionType,\
    SPENDADDRESS, SPENDWITNESS, SPENDMULTISIG, SPENDP2SHWITNESS, PAYTOADDRESS,\
    PAYTOOPRETURN, PAYTOWITNESS, PAYTOP2SHWITNESS, EXTERNAL
from trezorlib.tx_api import TxApi
from base58 import get_xpub_fingerprint, decode, to_address

import binascii
import json
#
# class HWITxApi(TxApi):
#     def __init__(self, tx):
#         self.tx = tx
#
#     def get_tx(self, txhash):


# This class extends the HardwareWalletClient for Trezor specific things
class TrezorClient(HardwareWalletClient):

    # device is an HID device that has already been opened.
    def __init__(self, device, path):
        super(TrezorClient, self).__init__(device)
        device.close()
        devices = HidTransport.enumerate()
        self.client = None
        for d in devices:
            if d[0] == path:
                transport = HidTransport(d)
                self.client = Trezor(transport)
                break

        # if it wasn't able to find a client, throw an error
        if not self.client:
            raise IOError("no Device")


    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        expanded_path = self.client.expand_path(path)
        output = self.client.get_public_node(expanded_path)
        return json.dumps({'xpub':output.xpub})

    # Must return a hex string with the signed transaction
    # The tx must be in the psbt format
    def sign_tx(self, tx):

        # Get this devices master key fingerprint
        master_key = self.client.get_public_node([])
        master_fp = get_xpub_fingerprint(master_key.xpub)

        # Prepare inputs
        inputs = []
        for psbt_in, txin in zip(tx.inputs, tx.tx.vin):
            txinputtype = TxInputType()
            # Check for 1 key
            if len(psbt_in.hd_keypaths) == 1:
                # Is this key ours
                if psbt_in.hd_keypaths.keys()[0] == master_fp:
                    # Set the keypath
                    txinputtype.address_n.extend(psbt_in.hd_keypaths.values()[0])
                else:
                    txinputtype.script_type = external

                    # Set the input stuff
                    txinputtype.prev_hash = txin.prevout.hash
                    txinputtype.prev_index = txin.prevout.n
                    txinputtype.sequence = txin.nSequence

                    # Set spend type
                    if txinputtype.script_type != EXTERNAL and psbt_in.non_witness_utxo:
                        txinputtype.script_type = SPENDADDRESS

            # Check for multisig (more than 1 key)
            elif len(psbt_in.hd_keypaths) > 1:
                # Find our keypath
                for fp, keypath in psbt_in.hd_keypaths.items():
                    if fp == master_fp:

                        # Set the keypaths
                        txinputtype.address_n.extend(keypath)

                        # Set the input stuff
                        txinputtype.prev_hash = txin.prevout.hash
                        txinputtype.prev_index = txin.prevout.n
                        txinputtype.sequence = txin.nSequence

                        # Set multisig
                        multisig = proto_types.MultisigRedeemScriptType(
                            pubkeys=[
                                proto_types.HDNodePathType(node=master_key, address_n=keypath),
                            ],
                            signatures=[b''],
                        )
                        txinputtype.multisig = multisig

                        break

                # Set spend type
                if psbt_in.non_witness_utxo:
                    txinputtype.script_type = SPENDMULTISIG

            if psbt_in.witness_utxo:
                # Check if the output is p2sh
                if psbt_in.witness_utxo.is_p2sh():
                    txinputtype.script_type = SPENDP2SHWITNESS
                else:
                    txinputtype.script_type = SPENDWITNESS

            # Set the amount
            if psbt_in.non_witness_utxo:
                txinputtype.amount = psbt_in.non_witness_utxo.vout[txin.prevout.n].nValue
            elif psbt_in.witness_utxo:
                txinputtype.amount = psbt_in.witness_utxo.nValue

            # append to inputs
            inputs.append(txinputtype)

        # prepare outputs
        outputs = []
        for out in tx.tx.vout:
            txoutput = TxOutputType()
            if out.is_p2pkh:
                txoutput.address = to_address(out.scriptPubKey[2:22], b"\x00")
                txoutput.amount = out.nValue
                txoutput.script_type = PAYTOADDRESS
            elif out.is_p2sh:
                txoutput.address = to_address(out.scriptPubKey[3:23], b"\x05")
            else:
                # TODO: Figure out what to do here. for now, just break
                break

            # append to outputs
            outputs.append(txoutput)

        # Sign the transaction
        self.client.set_tx_api()
        signed_tx = self.client.sign_tx("Bitcoin", inputs, outputs, tx.tx.nVersion, tx.tx.nLockTime)
        print(signed_tx)

        return

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

# Avoid circular imports
from hwi import HardwareWalletClient
