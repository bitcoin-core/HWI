# Trezor interaction script

from .hwwclient import HardwareWalletClient
from ckcc.client import ColdcardDevice
from ckcc.protocol import CCProtocolPacker
from ckcc.constants import MAX_BLK_LEN
from .base58 import xpub_main_2_test
from hashlib import sha256

import base64
import json
import io
import time

# This class extends the HardwareWalletClient for ColdCard specific things
class ColdCardClient(HardwareWalletClient):

    # device is an HID device that has already been opened.
    def __init__(self, device):
        super(ColdCardClient, self).__init__(device)
        self.device = ColdcardDevice(dev=device)

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        path = path.replace('h', '\'')
        path = path.replace('H', '\'')
        xpub = self.device.send_recv(CCProtocolPacker.get_xpub(path), timeout=None)
        if self.is_testnet:
            return {'xpub':xpub_main_2_test(xpub)}
        else:
            return {'xpub':xpub}

    # Must return a hex string with the signed transaction
    # The tx must be in the combined unsigned transaction format
    def sign_tx(self, tx):
        self.device.check_mitm()

        # Get psbt in hex and then make binary
        fd = io.BytesIO(base64.b64decode(tx.serialize()))

        # learn size (portable way)
        offset = 0
        sz = fd.seek(0, 2)
        fd.seek(0)

        left = sz
        chk = sha256()
        for pos in range(0, sz, MAX_BLK_LEN):
            here = fd.read(min(MAX_BLK_LEN, left))
            if not here: break
            left -= len(here)
            result = self.device.send_recv(CCProtocolPacker.upload(pos, sz, here))
            assert result == pos
            chk.update(here)

        # do a verify
        expect = chk.digest()
        result = self.device.send_recv(CCProtocolPacker.sha256())
        assert len(result) == 32
        if result != expect:
            raise ValueError("Wrong checksum:\nexpect: %s\n   got: %s" % (b2a_hex(expect).decode('ascii'), b2a_hex(result).decode('ascii')))

        # start the signing process
        ok = self.device.send_recv(CCProtocolPacker.sign_transaction(sz, expect), timeout=None)
        assert ok == None

        print("Waiting for OK on the Coldcard...")

        while 1:
            time.sleep(0.250)
            done = self.device.send_recv(CCProtocolPacker.get_signed_txn(), timeout=None)
            if done == None:
                continue
            break

        if len(done) != 2:
            raise ValueError('Failed: %r' % done)

        result_len, result_sha = done

        result = self.device.download_file(result_len, result_sha, file_number=1)
        return {'psbt':base64.b64encode(result).decode()}

    # Must return a base64 encoded string with the signed message
    # The message can be any string. keypath is the bip 32 derivation path for the key to sign with
    def sign_message(self, message, keypath):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

    # Display address of specified type on the device. Only supports single-key based addresses.
    def display_address(self, keypath, p2sh_p2wpkh, bech32):
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

    # Close the device
    def close(self):
        self.device.close()
