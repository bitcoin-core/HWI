# Trezor interaction script

from hwi import HardwareWalletClient
from trezorlib.transport_hid import HidTransport
from trezorlib.client import TrezorClient as Trezor
from trezorlib.types_trezor_pb2 import TxInputType, TxOutputType, TransactionType

import binascii

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

        # Prepare inputs
        for txin in tx.tx.vin:
            txinputtype = TxInputType()




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
