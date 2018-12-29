# Trezor interaction script

from ..hwwclient import HardwareWalletClient, UnavailableActionError
from ckcc.client import ColdcardDevice, COINKITE_VID, CKCC_PID
from ckcc.protocol import CCProtocolPacker
from ckcc.constants import MAX_BLK_LEN, AF_P2WPKH, AF_CLASSIC, AF_P2WPKH_P2SH
from ..base58 import xpub_main_2_test, get_xpub_fingerprint_hex
from hashlib import sha256

import base64
import json
import hid
import io
import time

CC_SIMULATOR_SOCK = '/tmp/ckcc-simulator.sock'
# Using the simulator: https://github.com/Coldcard/firmware/blob/master/unix/README.md

# This class extends the HardwareWalletClient for ColdCard specific things
class ColdcardClient(HardwareWalletClient):

    def __init__(self, path, password=''):
        super(ColdcardClient, self).__init__(path, password)
        # Simulator hard coded pipe socket
        if path == CC_SIMULATOR_SOCK:
            self.device = ColdcardDevice(sn=path)
        else:
            device = hid.device()
            device.open_path(path.encode())
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
        raise NotImplementedError('The Coldcard does not currently implement signmessage')

    # Display address of specified type on the device. Only supports single-key based addresses.
    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        keypath = keypath.replace('h', '\'')
        keypath = keypath.replace('H', '\'')

        if p2sh_p2wpkh:
            format = AF_P2WPKH_P2SH
        elif bech32:
            format = AF_P2WPKH
        else:
            format = AF_CLASSIC
        self.device.send_recv(CCProtocolPacker.show_address(keypath, format), timeout=None)

    # Setup a new device
    def setup_device(self, label='', passphrase=''):
        raise UnavailableActionError('The Coldcard does not support software setup')

    # Wipe this device
    def wipe_device(self):
        raise UnavailableActionError('The Coldcard does not support wiping via software')

    # Restore device from mnemonic or xprv
    def restore_device(self, label=''):
        raise UnavailableActionError('The Coldcard does not support restoring via software')

    # Begin backup process
    def backup_device(self, label='', passphrase=''):
        self.device.check_mitm()

        ok = self.device.send_recv(CCProtocolPacker.start_backup())
        assert ok == None

        while 1:
            time.sleep(0.250)
            done = self.device.send_recv(CCProtocolPacker.get_backup_file(), timeout=None)
            if done == None:
                continue
            break

        if len(done) != 2:
            raise ValueError('Failed: %r' % done)

        result_len, result_sha = done

        result = self.device.download_file(result_len, result_sha, file_number=0)
        filename = time.strftime('backup-%Y%m%d-%H%M.7z')
        open(filename, 'wb').write(result)
        return {'success': True, 'message': 'The backup has be written to {}'.format(filename)}

    # Close the device
    def close(self):
        self.device.close()

def enumerate(password=''):
    results = []
    for d in hid.enumerate(COINKITE_VID, CKCC_PID):
        d_data = {}

        path = d['path'].decode()
        d_data['type'] = 'coldcard'
        d_data['path'] = path

        try:
            client = ColdcardClient(path)
            master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
            d_data['fingerprint'] = get_xpub_fingerprint_hex(master_xpub)
            client.close()
        except Exception as e:
            d_data['error'] = "Could not open client or get fingerprint information: " + str(e)

        results.append(d_data)
    # Check if the simulator is there
    try:
        client = ColdcardClient(CC_SIMULATOR_SOCK)
        master_xpub = client.get_pubkey_at_path('m/0h')['xpub']

        d_data = {}
        d_data['fingerprint'] = get_xpub_fingerprint_hex(master_xpub)
        d_data['type'] = 'coldcard'
        d_data['path'] = CC_SIMULATOR_SOCK
        results.append(d_data)
        client.close()
    except RuntimeError as e:
        if str(e) == 'Cannot connect to simulator. Is it running?':
            pass
        else:
            raise e
    return results
