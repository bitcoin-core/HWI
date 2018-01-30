# Ledger interaction script

from hwi import HardwareWalletClient
from btchip.btchip import *
from btchip.btchipUtils import *
import base64
import json

# This class extends the HardwareWalletClient for Ledger Nano S specific things
class LedgerClient(HardwareWalletClient):

    # device is an HID device that has already been opened.
    # hacked in device support using btchip-python
    def __init__(self, device):
        super(LedgerClient, self).__init__(device)
        dongle = getDongle(True)
        self.app = btchip(dongle)
        self.device = device

    # Must return a dict with the pubkey, chaincode, and xpub. The pubkey and
    # chaincode must be hex strings.
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

    # Must return a hex string with the signed transaction
    # The tx must be in the combined unsigned transaction format
    def sign_tx(self, tx):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

    # Must return a base64 encoded string with the signed message
    # The message can be any string
    def sign_message(self, message, keypath):
        keypath = keypath[2:]
        # First display on screen what address you're signing for
        self.app.getWalletPublicKey(keypath, True)
        self.app.signMessagePrepare(keypath, message)
        signature = self.app.signMessageSign()

        # Make signature into standard bitcoin format
        rLength = signature[3]
        r = signature[4 : 4 + rLength]
        sLength = signature[4 + rLength + 1]
        s = signature[4 + rLength + 2:]
        if rLength == 33:
            r = r[1:]
        if sLength == 33:
            s = s[1:]
        r = str(r)
        s = str(s)

        sig = chr(27 + 4 + (signature[0] & 0x01)) + r + s

        return json.dumps({"signature":base64.b64encode(sig)})

    # Setup a new device
    def setup_device(self):
        raise NotImplementedError('The Ledger Nano S does not support software setup')

    # Wipe this device
    def wipe_device(self):
        raise NotImplementedError('The Ledger Nano S does not support wiping via software')

# Avoid circular imports
from hwi import HardwareWalletClient
