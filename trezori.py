# Trezor interaction script

from hwi import HardwareWalletClient
from trezorlib.client import TrezorClient as Trezor
from trezorlib.transport import get_transport
from trezorlib import coins
from trezorlib import messages as proto
from trezorlib import protobuf
from trezorlib import tools
from base58 import get_xpub_fingerprint, decode, to_address, xpub_main_2_test

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
        self.client = Trezor(transport=get_transport("hid:"+path.decode()))

        # if it wasn't able to find a client, throw an error
        if not self.client:
            raise IOError("no Device")


    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        expanded_path = tools.parse_path(path)
        output = self.client.get_public_node(expanded_path)
        if self.is_testnet:
            return json.dumps({'xpub':xpub_main_2_test(output.xpub)})
        else:
            return json.dumps({'xpub':output.xpub})

    # Must return a hex string with the signed transaction
    # The tx must be in the psbt format
    def sign_tx(self, tx):

        # Get this devices master key fingerprint
        master_key = self.client.get_public_node([0])
        master_fp = get_xpub_fingerprint(master_key.xpub)

        # Prepare inputs
        inputs = []
        for psbt_in, txin in zip(tx.inputs, tx.tx.vin):
            txinputtype = proto.TxInputType()

            # Set the input stuff
            txinputtype.prev_hash = txin.prevout.hash
            txinputtype.prev_index = txin.prevout.n
            txinputtype.sequence = txin.nSequence

            # Check for 1 key
            if len(psbt_in.hd_keypaths) == 1:
                # Is this key ours
                if psbt_in.hd_keypaths.keys()[0] == master_fp:
                    # Set the keypath
                    txinputtype.address_n.extend(psbt_in.hd_keypaths.values()[0])
                else:
                    txinputtype.script_type = proto.InputScriptType.EXTERNAL

                    # Set spend type
                    if txinputtype.script_type != proto.InputScriptType.EXTERNAL and psbt_in.non_witness_utxo:
                        txinputtype.script_type = proto.InputScriptType.SPENDADDRESS

            # Check for multisig (more than 1 key)
            elif len(psbt_in.hd_keypaths) > 1:
                # Find our keypath
                for fp, keypath in psbt_in.hd_keypaths.items():
                    if fp == master_fp:

                        # Set the keypaths
                        txinputtype.address_n.extend(keypath)

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
                    txinputtype.script_type = proto.InputScriptType.SPENDMULTISIG

            if psbt_in.witness_utxo:
                # Check if the output is p2sh
                if psbt_in.witness_utxo.is_p2sh():
                    txinputtype.script_type = proto.InputScriptType.SPENDP2SHWITNESS
                else:
                    txinputtype.script_type = proto.InputScriptType.SPENDWITNESS

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
            p2sh_version = b'\c4'
        else:
            p2pkh_version = b'\x00'
            p2sh_version = b'\x05'

        # prepare outputs
        outputs = []
        for out in tx.tx.vout:
            txoutput = proto.TxOutputType()
            if out.is_p2pkh:
                txoutput.address = to_address(out.scriptPubKey[2:22], p2pkh_version)
                txoutput.amount = out.nValue
                txoutput.script_type = proto.OutputScriptType.PAYTOADDRESS
            elif out.is_p2sh:
                txoutput.address = to_address(out.scriptPubKey[3:23], p2sh_version)
                txoutput.amount = out.nValue
                txoutput.script_type = proto.OutputScriptType.PAYTOADDRESS
            else:
                # TODO: Figure out what to do here. for now, just break
                break

            # append to outputs
            outputs.append(txoutput)

        # Sign the transaction
        if self.is_testnet:
            self.client.set_tx_api(coins.tx_api['Testnet'])
            signed_tx = self.client.sign_tx("Testnet", inputs, outputs, tx.tx.nVersion, tx.tx.nLockTime)
        else:
            self.client.set_tx_api(coins.tx_api['Bitcoin'])
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
