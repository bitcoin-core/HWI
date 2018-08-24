# KeepKey interaction script

from base58 import xpub_main_2_test
from hwi import HardwareWalletClient
from keepkeylib.transport_hid import HidTransport
from keepkeylib.client import KeepKeyClient as KeepKey

import binascii
import json

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
        expanded_path = self.client.expand_path(path)
        output = self.client.get_public_node(expanded_path)
        if self.is_testnet:
            return json.dumps({'xpub':xpub_main_2_test(output.xpub)})
        else:
            return json.dumps({'xpub':output.xpub})

    # Must return a hex string with the signed transaction
    # The tx must be in the combined unsigned transaction format
    def sign_tx(self, tx):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

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
