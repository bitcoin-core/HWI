# Ledger interaction script

from hwi import HardwareWalletClient
from btchip.btchip import *
from btchip.btchipUtils import *
import base64
import json
import struct
import base58
from serializations import hash256, hash160

# This class extends the HardwareWalletClient for Ledger Nano S specific things
class LedgerClient(HardwareWalletClient):

    # device is an HID device that has already been opened.
    # hacked in device support using btchip-python
    def __init__(self, device):
        super(LedgerClient, self).__init__(device)
        dongle = getDongle(True)
        self.app = btchip(dongle)
        self.device = device

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        path = path[2:]
        # This call returns raw uncompressed pubkey, chaincode
        pubkey = self.app.getWalletPublicKey(path)
        if path != "":
            parent_path = ""
            for ind in path.split("/")[:-1]:
                parent_path += ind+"/"
            parent_path = parent_path[:-1]

            # Get parent key fingerprint
            parent = self.app.getWalletPublicKey(parent_path)
            fpr = hash160(compress_public_key(parent["publicKey"]))[:4]

            # Compute child info
            childstr = path.split("/")[-1]
            hard = 0
            if childstr[-1] == "'":
                childstr = childstr[:-1]
                hard = 0x80000000
            child = struct.pack(">I", int(childstr)+hard)
        # Special case for m
        else:
            child = "00000000".decode('hex')
            fpr = child

        chainCode = pubkey["chainCode"]
        publicKey = compress_public_key(pubkey["publicKey"])

        depth = len(path.split("/")) if len(path) > 0 else 0
        depth = struct.pack("B", depth)

        version = "0488B21E".decode('hex')
        extkey = version+depth+fpr+child+chainCode+publicKey
        checksum = hash256(extkey)[:4]

        return json.dumps({"xpub":base58.encode(extkey+checksum)})

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
