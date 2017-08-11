# Ledger interaction script

from hwi import HardwareWalletClient

# This class extends the HardwareWalletClient for Digital Bitbox specific things
class LedgerClient(HardwareWalletClient):

    # device is an HID device that has already been opened.
    def __init__(self, device):
        super(LedgerClient, self).__init__(device)
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
