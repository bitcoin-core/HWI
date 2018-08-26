# Trezor interaction script

from hwi import HardwareWalletClient
from ckcc.client import ColdcardDevice
from ckcc.protocol import CCProtocolPacker

import bech32
import binascii
import json

# This class extends the HardwareWalletClient for ColdCard specific things
class ColdCardClient(HardwareWalletClient):

    # device is an HID device that has already been opened.
    def __init__(self, device):
        self.device = ColdcardDevice(dev=device)

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        path = path.replace('h', '\'')
        path = path.replace('H', '\'')
        xpub = self.device.send_recv(CCProtocolPacker.get_xpub(path), timeout=None)
        if self.is_testnet:
            return json.dumps({'xpub':xpub_main_2_test(xpub)})
        else:
            return json.dumps({'xpub':xpub})

    # Must return a hex string with the signed transaction
    # The tx must be in the combined unsigned transaction format
    def sign_tx(self, tx):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

    # Must return a base64 encoded string with the signed message
    # The message can be any string. keypath is the bip 32 derivation path for the key to sign with
    def sign_message(self, message, keypath):
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
