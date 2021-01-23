# Coldcard interaction script

from typing import Dict, Union

from ..hwwclient import HardwareWalletClient
from ..errors import (
    ActionCanceledError,
    BadArgumentError,
    DeviceBusyError,
    DeviceFailureError,
    UnavailableActionError,
    common_err_msgs,
    handle_errors,
)
from .ckcc.client import (
    ColdcardDevice,
    COINKITE_VID,
    CKCC_PID,
)
from .ckcc.protocol import (
    CCProtocolPacker,
    CCBusyError,
    CCProtoError,
    CCUserRefused,
)
from .ckcc.constants import (
    MAX_BLK_LEN,
    AF_P2WPKH,
    AF_CLASSIC,
    AF_P2WPKH_P2SH,
    AF_P2WSH,
    AF_P2SH,
    AF_P2WSH_P2SH,
)
from .ckcc.utils import dfu_parse
from .ckcc.sigheader import (
    FW_HEADER_SIZE,
    FW_HEADER_OFFSET,
    FW_HEADER_MAGIC,
    FWH_PY_FORMAT,
)
from ..base58 import (
    get_xpub_fingerprint,
    xpub_main_2_test,
)
from ..key import (
    ExtendedKey,
)
from ..serializations import (
    PSBT,
)
from hashlib import sha256

import base64
import ecdsa
import hid
import io
import sys
import time
import struct
from binascii import hexlify, a2b_hex, b2a_hex

CC_SIMULATOR_SOCK = '/tmp/ckcc-simulator.sock'
# Using the simulator: https://github.com/Coldcard/firmware/blob/master/unix/README.md


def str_to_int_path(xfp, path):
    # convert text  m/34'/33/44 into BIP174 binary compat format
    # - include hex for fingerprint (m) as first arg

    rv = [struct.unpack('<I', a2b_hex(xfp))[0]]
    for i in path.split('/'):
        if i == 'm':
            continue
        if not i:
            continue      # trailing or duplicated slashes

        if i[-1] in "'phHP":
            assert len(i) >= 2, i
            here = int(i[:-1]) | 0x80000000
        else:
            here = int(i)
            assert 0 <= here < 0x80000000, here

        rv.append(here)

    return rv


FIRMWARE_KEYS = [
    bytearray([0xb4, 0xcb, 0x41, 0x26, 0xf7, 0xe1, 0x6c, 0xf3, 0x8f, 0xf2, 0xb4,
               0x71, 0x1d, 0xfb, 0x23, 0x01, 0x0d, 0x76, 0xd6, 0x66, 0xa7, 0x8a,
               0xa3, 0x6c, 0x9b, 0x53, 0xf9, 0xf6, 0x7b, 0x58, 0x18, 0x05, 0x58,
               0x0b, 0x3b, 0xe9, 0x31, 0xc4, 0x9f, 0xb8, 0x44, 0x04, 0x3c, 0x11,
               0x96, 0x08, 0x0f, 0x47, 0x81, 0x25, 0xed, 0x37, 0x7a, 0x23, 0x9e,
               0x4a, 0xaf, 0xb7, 0x18, 0x38, 0xba, 0x38, 0x04, 0xda]),
    bytearray([0xd6, 0xa2, 0xc8, 0x1d, 0x1c, 0x81, 0x5e, 0xdf, 0xa6, 0x0c, 0x29,
               0x6d, 0xb8, 0x57, 0x8f, 0x8d, 0x5e, 0x29, 0x69, 0x92, 0xce, 0xd1,
               0x78, 0xc1, 0x7b, 0x20, 0xd7, 0x31, 0x7b, 0xa1, 0x96, 0xb5, 0x3d,
               0xef, 0x1b, 0x0c, 0xaa, 0x79, 0x1a, 0xc3, 0x45, 0x58, 0xc4, 0xc8,
               0x8a, 0x2d, 0xeb, 0xff, 0xfe, 0x9b, 0x82, 0x01, 0x87, 0x5f, 0x5e,
               0xbc, 0x96, 0xa5, 0xe5, 0x4f, 0xc7, 0x68, 0xfe, 0x9f]),
    bytearray([0x42, 0xef, 0x66, 0x01, 0x56, 0xc4, 0xcf, 0x95, 0xf4, 0xb5, 0xf0,
               0x38, 0x64, 0x11, 0x26, 0xc5, 0x99, 0x39, 0xc1, 0x66, 0x32, 0x06,
               0x12, 0x14, 0x4c, 0x25, 0x9c, 0x68, 0x35, 0x8c, 0xd3, 0xba, 0x24,
               0x78, 0xde, 0x8c, 0x52, 0xab, 0xdf, 0x6c, 0xb8, 0xbf, 0x09, 0x78,
               0x03, 0xbb, 0x63, 0x3a, 0x11, 0x01, 0xd9, 0x0e, 0xa4, 0x7a, 0x73,
               0x8f, 0xbf, 0x18, 0x3b, 0x7f, 0xf0, 0x0a, 0x7b, 0xc8]),
    bytearray([0x67, 0x60, 0x54, 0x56, 0x82, 0x0c, 0xec, 0xc5, 0x1d, 0xbc, 0x82,
               0x08, 0x16, 0xc1, 0x39, 0xef, 0xf5, 0xbf, 0xba, 0x32, 0x7c, 0xce,
               0x5f, 0xe3, 0x74, 0x1e, 0x62, 0xd7, 0xe9, 0xfc, 0xc5, 0x4c, 0x8a,
               0xe8, 0x11, 0x8d, 0xc3, 0xad, 0xc2, 0x13, 0x92, 0x29, 0x4f, 0x2a,
               0xea, 0xd2, 0xf8, 0xa4, 0xc4, 0xd5, 0x7c, 0xfe, 0x12, 0x05, 0x45,
               0x3b, 0x54, 0x89, 0x59, 0x07, 0xda, 0xd6, 0xd7, 0x88]),
    bytearray([0x43, 0xb1, 0xcf, 0x37, 0xd2, 0x7c, 0x89, 0x1f, 0x5b, 0xfe, 0xac,
               0xf3, 0xba, 0x33, 0xfc, 0x95, 0x81, 0xd9, 0xe7, 0xdd, 0x25, 0x95,
               0xef, 0x14, 0xdd, 0xef, 0x97, 0xbb, 0x33, 0xf3, 0xd8, 0xa7, 0x34,
               0x2b, 0x7a, 0x97, 0xba, 0xb3, 0xaa, 0x73, 0xe7, 0x9d, 0x41, 0x32,
               0xd8, 0xfc, 0xa1, 0x17, 0x66, 0xb5, 0x0b, 0xfe, 0x63, 0x40, 0x21,
               0x89, 0xc9, 0x92, 0x7b, 0x8e, 0x72, 0xdf, 0x0b, 0x59])
]
DEV_KEY = FIRMWARE_KEYS[0] # Warn when this key is used for signing as it is publicly known key for development only


def verify_firmware(firmware_data):
    # Skip DFU header
    firmware_data = firmware_data[293:]

    header = firmware_data[FW_HEADER_OFFSET:FW_HEADER_OFFSET + FW_HEADER_SIZE]
    magic, _, _, pubkey_num, firmware_length, _, _, _, signature = struct.unpack(FWH_PY_FORMAT, header)
    assert magic == FW_HEADER_MAGIC
    msg = sha256(firmware_data[0:FW_HEADER_OFFSET + FW_HEADER_SIZE - 64])
    msg.update(firmware_data[FW_HEADER_OFFSET + FW_HEADER_SIZE:firmware_length])
    digest = sha256(msg.digest()).digest()

    if pubkey_num == 0:
        print("Warning: This firmware was signed using the publicly available dev key and not a Coinkite official key", file=sys.stderr)

    key = ecdsa.VerifyingKey.from_string(FIRMWARE_KEYS[pubkey_num], curve=ecdsa.curves.SECP256k1)
    try:
        return key.verify_digest(signature, digest)
    except ecdsa.BadSignatureError:
        return False


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
            xpub_obj = ExtendedKey.deserialize(xpub)
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
                if keypath.fingerprint == master_fp and key not in psbt_in.partial_sigs:
                    our_keys += 1
            if our_keys > passes:
                passes = our_keys

        for _ in range(passes):
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

    @coldcard_exception
    def sign_message(self, message: Union[str, bytes], keypath: str) -> Dict[str, str]:
        self.device.check_mitm()
        keypath = keypath.replace('h', '\'')
        keypath = keypath.replace('H', '\'')

        msg = message
        if not isinstance(message, bytes):
            msg = message.encode()
        ok = self.device.send_recv(
            CCProtocolPacker.sign_message(msg, keypath, AF_CLASSIC), timeout=None
        )
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

        _, raw = done

        sig = str(base64.b64encode(raw), 'ascii').replace('\n', '')
        return {"signature": sig}

    # Display address of specified type on the device.
    @coldcard_exception
    def display_address(self, keypath, p2sh_p2wpkh, bech32, redeem_script=None, descriptor=None):
        self.device.check_mitm()
        keypath = keypath.replace('h', '\'')
        keypath = keypath.replace('H', '\'')

        if p2sh_p2wpkh:
            addr_fmt = AF_P2WSH_P2SH if redeem_script else AF_P2WPKH_P2SH
        elif bech32:
            addr_fmt = AF_P2WSH if redeem_script else AF_P2WPKH
        else:
            addr_fmt = AF_P2SH if redeem_script else AF_CLASSIC

        if redeem_script:
            keypaths = keypath.split(',')
            script = a2b_hex(redeem_script)

            N = len(keypaths)

            if not 1 <= N <= 15:
                raise BadArgumentError("Must provide 1 to 15 keypaths to display a multisig address")

            min_signers = script[0] - 80
            if not 1 <= min_signers <= N:
                raise BadArgumentError("Either the redeem script provided is invalid or the keypaths provided are insufficient")

            if not script[-1] == 0xAE:
                raise BadArgumentError("The redeem script provided is not a multisig. Only multisig scripts can be displayed.")

            if not script[-2] == 80 + N:
                raise BadArgumentError("Invalid redeem script, second last byte should encode N")

            xfp_paths = []
            for xfp in keypaths:
                if '/' not in xfp:
                    raise BadArgumentError('Invalid keypath. Needs a XFP/path: ' + xfp)
                xfp, p = xfp.split('/', 1)

                xfp_paths.append(str_to_int_path(xfp, p))

            payload = CCProtocolPacker.show_p2sh_address(min_signers, xfp_paths, script, addr_fmt=addr_fmt)
        # single-sig
        else:
            payload = CCProtocolPacker.show_address(keypath, addr_fmt=addr_fmt)

        address = self.device.send_recv(payload, timeout=None)

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

    # Verify firmware file then load it onto device
    @coldcard_exception
    def update_firmware(self, filename: str) -> Dict[str, bool]:
        with open(filename, 'rb') as fd:
            # learn size (portable way)
            offset = 0
            sz = fd.seek(0, 2)
            fd.seek(0)

            # Unwrap DFU contents, if needed. Also handles raw binary file.
            try:
                if fd.read(5) == b'DfuSe':
                    # expecting a DFU-wrapped file.
                    fd.seek(0)
                    offset, sz, *_ = dfu_parse(fd)
                else:
                    # assume raw binary
                    pass

                assert sz % 256 == 0, "un-aligned size: %s" % sz
                fd.seek(offset + FW_HEADER_OFFSET)
                hdr = fd.read(FW_HEADER_SIZE)

                magic = struct.unpack_from("<I", hdr)[0]
            except Exception:
                magic = None

            if magic != FW_HEADER_MAGIC:
                raise BadArgumentError('{} has an invalid magic header for a firmware file.'.format(filename))

            # Read the whole firmware to verify the signature
            fd.seek(0)
            data = fd.read()
            if not verify_firmware(data):
                raise BadArgumentError('Firmware signature is invalid')

            fd.seek(offset)

            left = sz
            chk = sha256()
            for pos in range(0, sz, MAX_BLK_LEN):
                here = fd.read(min(MAX_BLK_LEN, left))
                if not here:
                    break
                left -= len(here)
                result = self.device.send_recv(CCProtocolPacker.upload(pos, sz, here))
                assert result == pos, "Got back: %r" % result
                chk.update(here)

        # do a verify
        expect = chk.digest()
        result = self.device.send_recv(CCProtocolPacker.sha256())
        assert len(result) == 32
        if result != expect:
            raise DeviceFailureError("Wrong checksum:\nexpect: %s\n   got: %s" % (b2a_hex(expect).decode('ascii'), b2a_hex(result).decode('ascii')))

        # AFTER fully uploaded and verified, write a copy of the signature header
        # onto the end of flash. Bootrom uses this to check entire file uploaded.
        result = self.device.send_recv(CCProtocolPacker.upload(sz, sz + FW_HEADER_SIZE, hdr))
        assert result == sz, "failed to write trailer"

        # check also SHA after that!
        chk.update(hdr)
        expect = chk.digest()
        final_chk = self.device.send_recv(CCProtocolPacker.sha256())
        assert expect == final_chk, "Checksum mismatch after all that?"

        self.device.send_recv(CCProtocolPacker.reboot())

        return {'success': True}

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
