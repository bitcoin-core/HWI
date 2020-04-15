# Coldcard interaction script

from binascii import b2a_hex
from ..hwwclient import HardwareWalletClient
from ..errors import ActionCanceledError, BadArgumentError, DeviceBusyError, DeviceFailureError, UnavailableActionError, common_err_msgs, handle_errors
from .ckcc.client import ColdcardDevice, COINKITE_VID, CKCC_PID
from .ckcc.protocol import CCProtocolPacker, CCBusyError, CCProtoError, CCUserRefused
from .ckcc.constants import MAX_BLK_LEN, AF_P2WPKH, AF_CLASSIC, AF_P2WPKH_P2SH
from ..base58 import get_xpub_fingerprint, xpub_main_2_test
from ..serializations import ExtendedKey, PSBT
from hashlib import sha256

import base64
import hid
import io
import sys
import time
import struct
from binascii import hexlify

CC_SIMULATOR_SOCK = '/tmp/ckcc-simulator.sock'
# Using the simulator: https://github.com/Coldcard/firmware/blob/master/unix/README.md

def coldcard_exception(f):
    def func(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except CCProtoError as e:
            raise BadArgumentError(str(e))
        except CCUserRefused:
            raise ActionCanceledError('{} canceled'.format(f.__name__))
        except CCBusyError as e:
            raise DeviceBusyError(str(e))
    return func

# This class extends the HardwareWalletClient for ColdCard specific things
class ColdcardClient(HardwareWalletClient):

    def __init__(self, path, password='', expert=False):
        super(ColdcardClient, self).__init__(path, password, expert)
        # Simulator hard coded pipe socket
        if path == CC_SIMULATOR_SOCK:
            self.device = ColdcardDevice(sn=path)
        else:
            device = hid.device()
            device.open_path(path.encode())
            self.device = ColdcardDevice(dev=device)

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    @coldcard_exception
    def get_pubkey_at_path(self, path):
        self.device.check_mitm()
        path = path.replace('h', '\'')
        path = path.replace('H', '\'')
        xpub = self.device.send_recv(CCProtocolPacker.get_xpub(path), timeout=None)
        if self.is_testnet:
            result = {'xpub': xpub_main_2_test(xpub)}
        else:
            result = {'xpub': xpub}
        if self.expert:
            xpub_obj = ExtendedKey()
            xpub_obj.deserialize(xpub)
            result.update(xpub_obj.get_printable_dict())
        return result

    def get_master_fingerprint_hex(self):
        # quick method to get fingerprint of wallet
        return hexlify(struct.pack('<I', self.device.master_fingerprint)).decode()

    # Must return a hex string with the signed transaction
    # The tx must be in the combined unsigned transaction format
    @coldcard_exception
    def sign_tx(self, tx):
        self.device.check_mitm()

        # Get this devices master key fingerprint
        xpub = self.device.send_recv(CCProtocolPacker.get_xpub('m/0\''), timeout=None)
        master_fp = get_xpub_fingerprint(xpub)

        # For multisigs, we may need to do multiple passes if we appear in an input multiple times
        passes = 1
        for psbt_in in tx.inputs:
            our_keys = 0
            for key in psbt_in.hd_keypaths.keys():
                keypath = psbt_in.hd_keypaths[key]
                if keypath[0] == master_fp and key not in psbt_in.partial_sigs:
                    our_keys += 1
            if our_keys > passes:
                passes = our_keys

        for i in range(0, passes):
            # Get psbt in hex and then make binary
            fd = io.BytesIO(base64.b64decode(tx.serialize()))

            # learn size (portable way)
            sz = fd.seek(0, 2)
            fd.seek(0)

            left = sz
            chk = sha256()
            for pos in range(0, sz, MAX_BLK_LEN):
                here = fd.read(min(MAX_BLK_LEN, left))
                if not here:
                    break
                left -= len(here)
                result = self.device.send_recv(CCProtocolPacker.upload(pos, sz, here))
                assert result == pos
                chk.update(here)

            # do a verify
            expect = chk.digest()
            result = self.device.send_recv(CCProtocolPacker.sha256())
            assert len(result) == 32
            if result != expect:
                raise DeviceFailureError("Wrong checksum:\nexpect: %s\n   got: %s" % (b2a_hex(expect).decode('ascii'), b2a_hex(result).decode('ascii')))

            # start the signing process
            ok = self.device.send_recv(CCProtocolPacker.sign_transaction(sz, expect), timeout=None)
            assert ok is None
            if self.device.is_simulator:
                self.device.send_recv(CCProtocolPacker.sim_keypress(b'y'))

            print("Waiting for OK on the Coldcard...", file=sys.stderr)

            while 1:
                time.sleep(0.250)
                done = self.device.send_recv(CCProtocolPacker.get_signed_txn(), timeout=None)
                if done is None:
                    continue
                break

            if len(done) != 2:
                raise DeviceFailureError('Failed: %r' % done)

            result_len, result_sha = done

            result = self.device.download_file(result_len, result_sha, file_number=1)

            tx = PSBT()
            tx.deserialize(base64.b64encode(result).decode())
        return {'psbt': tx.serialize()}

    # Must return a base64 encoded string with the signed message
    # The message can be any string. keypath is the bip 32 derivation path for the key to sign with
    @coldcard_exception
    def sign_message(self, message, keypath):
        self.device.check_mitm()
        keypath = keypath.replace('h', '\'')
        keypath = keypath.replace('H', '\'')

        ok = self.device.send_recv(CCProtocolPacker.sign_message(message.encode(), keypath, AF_CLASSIC), timeout=None)
        assert ok is None
        if self.device.is_simulator:
            self.device.send_recv(CCProtocolPacker.sim_keypress(b'y'))

        while 1:
            time.sleep(0.250)
            done = self.device.send_recv(CCProtocolPacker.get_signed_msg(), timeout=None)
            if done is None:
                continue

            break

        if len(done) != 2:
            raise DeviceFailureError('Failed: %r' % done)

        addr, raw = done

        sig = str(base64.b64encode(raw), 'ascii').replace('\n', '')
        return {"signature": sig}

    # Display address of specified type on the device. Only supports single-key based addresses.
    @coldcard_exception
    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        self.device.check_mitm()
        keypath = keypath.replace('h', '\'')
        keypath = keypath.replace('H', '\'')

        if p2sh_p2wpkh:
            format = AF_P2WPKH_P2SH
        elif bech32:
            format = AF_P2WPKH
        else:
            format = AF_CLASSIC
        address = self.device.send_recv(CCProtocolPacker.show_address(keypath, format), timeout=None)
        if self.device.is_simulator:
            self.device.send_recv(CCProtocolPacker.sim_keypress(b'y'))
        return {'address': address}

    # Setup a new device
    def setup_device(self, label='', passphrase=''):
        raise UnavailableActionError('The Coldcard does not support software setup')

    # Wipe this device
    def wipe_device(self):
        raise UnavailableActionError('The Coldcard does not support wiping via software')

    # Restore device from mnemonic or xprv
    def restore_device(self, label='', word_count=24):
        raise UnavailableActionError('The Coldcard does not support restoring via software')

    # Begin backup process
    @coldcard_exception
    def backup_device(self, label='', passphrase=''):
        self.device.check_mitm()

        ok = self.device.send_recv(CCProtocolPacker.start_backup())
        assert ok is None
        if self.device.is_simulator:
            self.device.send_recv(CCProtocolPacker.sim_keypress(b'y'))

        while 1:
            if self.device.is_simulator: # For the simulator, work through the password quiz. Eventually pressing 1 will work
                self.device.send_recv(CCProtocolPacker.sim_keypress(b'1'))

            time.sleep(0.250)
            done = self.device.send_recv(CCProtocolPacker.get_backup_file(), timeout=None)
            if done is None:
                continue
            break

        if len(done) != 2:
            raise DeviceFailureError('Failed: %r' % done)

        result_len, result_sha = done

        result = self.device.download_file(result_len, result_sha, file_number=0)
        filename = time.strftime('backup-%Y%m%d-%H%M.7z')
        open(filename, 'wb').write(result)
        return {'success': True, 'message': 'The backup has been written to {}'.format(filename)}

    # Close the device
    def close(self):
        self.device.close()

    # Prompt pin
    def prompt_pin(self):
        raise UnavailableActionError('The Coldcard does not need a PIN sent from the host')

    # Send pin
    def send_pin(self, pin):
        raise UnavailableActionError('The Coldcard does not need a PIN sent from the host')

    # Toggle passphrase
    def toggle_passphrase(self):
        raise UnavailableActionError('The Coldcard does not support toggling passphrase from the host')

def enumerate(password=''):
    results = []
    devices = hid.enumerate(COINKITE_VID, CKCC_PID)
    devices.append({'path': CC_SIMULATOR_SOCK.encode()})
    for d in devices:
        d_data = {}

        path = d['path'].decode()
        d_data['type'] = 'coldcard'
        d_data['model'] = 'coldcard'
        d_data['path'] = path
        d_data['needs_pin_sent'] = False
        d_data['needs_passphrase_sent'] = False

        if path == CC_SIMULATOR_SOCK:
            d_data['model'] += '_simulator'

        client = None
        with handle_errors(common_err_msgs["enumerate"], d_data):
            try:
                client = ColdcardClient(path)
                d_data['fingerprint'] = client.get_master_fingerprint_hex()
            except RuntimeError as e:
                # Skip the simulator if it's not there
                if str(e) == 'Cannot connect to simulator. Is it running?':
                    continue
                else:
                    raise e

        if client:
            client.close()

        results.append(d_data)

    return results
