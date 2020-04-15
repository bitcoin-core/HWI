from .base58 import get_xpub_fingerprint_hex

# This is an abstract class that defines all of the methods that each Hardware
# wallet subclass must implement.
class HardwareWalletClient(object):

    # device is an HID device that has already been opened.
    def __init__(self, path, password, expert):
        self.path = path
        self.password = password
        self.message_magic = b"\x18Bitcoin Signed Message:\n"
        self.is_testnet = False
        self.fingerprint = None
        self.xpub_cache = {}
        self.expert = expert

    # Get the master BIP 44 pubkey
    def get_master_xpub(self):
        return self.get_pubkey_at_path('m/44\'/0\'/0\'')

    # Get the master fingerprint
    def get_master_fingerprint_hex(self):
        master_xpub = self.get_pubkey_at_path('m/0h')['xpub']
        return get_xpub_fingerprint_hex(master_xpub)

    # Must return a dict with the xpub
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
    # The message can be any string. keypath is the bip 32 derivation path for the key to sign with
    def sign_message(self, message, keypath):
        raise NotImplementedError('The HardwareWalletClient base class does not '
                                  'implement this method')

    # Setup a new device
    def setup_device(self, label='', passphrase=''):
        raise NotImplementedError('The HardwareWalletClient base class does not '
                                  'implement this method')

    # Wipe this device
    def wipe_device(self):
        raise NotImplementedError('The HardwareWalletClient base class does not '
                                  'implement this method')

    # Restore device from mnemonic or xprv
    def restore_device(self, label='', word_count=24):
        raise NotImplementedError('The HardwareWalletClient base class does not implement this method')

    # Begin backup process
    def backup_device(self, label='', passphrase=''):
        raise NotImplementedError('The HardwareWalletClient base class does not implement this method')

    # Close the device
    def close(self):
        raise NotImplementedError('The HardwareWalletClient base class does not '
                                  'implement this method')

    # Prompt pin
    def prompt_pin(self):
        raise NotImplementedError('The HardwareWalletClient base class does not implement this method')

    # Send pin
    def send_pin(self):
        raise NotImplementedError('The HardwareWalletClient base class does not implement this method')

    # Toggle passphrase
    def toggle_passphrase(self):
        raise NotImplementedError('The HardwareWalletClient base class does not implement this method')
