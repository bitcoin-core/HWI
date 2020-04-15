# Digital Bitbox interaction script

import hid
import struct
import json
import base64
import pyaes
import hashlib
import hmac
import os
import binascii
import logging
import socket
import sys
import time

from ..hwwclient import HardwareWalletClient
from ..errors import ActionCanceledError, BadArgumentError, DeviceFailureError, DeviceAlreadyInitError, DEVICE_NOT_INITIALIZED, DeviceNotReadyError, NoPasswordError, UnavailableActionError, common_err_msgs, handle_errors
from ..serializations import CTransaction, ExtendedKey, hash256, ser_sig_der, ser_sig_compact, ser_compact_size
from ..base58 import get_xpub_fingerprint, xpub_main_2_test

applen = 225280 # flash size minus bootloader length
chunksize = 8 * 512
usb_report_size = 64 # firmware > v2.0
report_buf_size = 4096 # firmware v2.0.0
boot_buf_size_send = 4098
boot_buf_size_reply = 256
HWW_CID = 0xFF000000
HWW_CMD = 0x80 + 0x40 + 0x01

DBB_VENDOR_ID = 0x03eb
DBB_DEVICE_ID = 0x2402

# Errors codes from the device
bad_args = [
    102, # The password length must be at least " STRINGIFY(PASSWORD_LEN_MIN) " characters.
    103, # No input received.
    104, # Invalid command.
    105, # Only one command allowed at a time.
    109, # JSON parse error.
    204, # Invalid seed.
    253, # Incorrect serialized pubkey length. A 33-byte hexadecimal value (66 characters) is expected.
    254, # Incorrect serialized pubkey hash length. A 32-byte hexadecimal value (64 characters) is expected.
    256, # Failed to pair with second factor, because the previously received hash of the public key does not match the computed hash of the public key.
    300, # Incorrect pubkey length. A 33-byte hexadecimal value (66 characters) is expected.
    301, # Incorrect hash length. A 32-byte hexadecimal value (64 characters) is expected.
    304, # Incorrect TFA pin.
    411, # Filenames limited to alphanumeric values, hyphens, and underscores.
    412, # Please provide an encryption key.
    112, # Device password matches reset password. Disabling reset password.
    251, # Could not generate key.
]

bad_args.extend([str(x) for x in bad_args])

device_failures = [
    101, # Please set a password.
    107, # Output buffer overflow.
    200, # Seed creation requires an SD card for automatic encrypted backup of the seed.
    250, # Master key not present.
    252, # Could not generate ECDH secret.
    303, # Could not sign.
    400, # Please insert SD card.
    401, # Could not mount the SD card.
    402, # Could not open a file to write - it may already exist.
    403, # Could not open the directory.
    405, # Could not write the file.
    407, # Could not read the file.
    408, # May not have erased all files (or no file present).
    410, # Backup file does not match wallet.
    500, # Chip communication error.
    501, # Could not read flash.
    502, # Could not encrypt.
    110, # Too many failed access attempts. Device reset.
    111, # Device locked. Erase device to access this command.
    113, # Due to many login attempts, the next login requires holding the touch button for 3 seconds.
    900, # attempts remain before the device is reset.
    901, # Ignored for non-embedded testing.
    902, # Too many backup files to read. The list is truncated.
    903, # attempts remain before the device is reset. The next login requires holding the touch button.
]

device_failures.extend([str(x) for x in device_failures])

cancels = [
    600, # Aborted by user.
    601, # Touchbutton timed out.
]

cancels.extend([str(x) for x in cancels])

ERR_MEM_SETUP = 503 # Device initialization in progress.

class DBBError(Exception):
    def __init__(self, error):
        Exception.__init__(self)
        self.error = error

    def get_error(self):
        return self.error['error']['message']

    def get_code(self):
        return self.error['error']['code']

    def __str__(self):
        return 'Error: {}, Code: {}'.format(self.error['error']['message'], self.error['error']['code'])

def digitalbitbox_exception(f):
    def func(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except DBBError as e:
            if e.get_code() in bad_args:
                raise BadArgumentError(e.get_error())
            elif e.get_code() in device_failures:
                raise DeviceFailureError(e.get_error())
            elif e.get_code() in cancels:
                raise ActionCanceledError(e.get_error())
            elif e.get_code() == ERR_MEM_SETUP or e.get_code() == str(ERR_MEM_SETUP):
                raise DeviceNotReadyError(e.get_error())

    return func

def aes_encrypt_with_iv(key, iv, data):
    aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
    aes = pyaes.Encrypter(aes_cbc)
    e = aes.feed(data) + aes.feed()  # empty aes.feed() appends pkcs padding
    return e


def aes_decrypt_with_iv(key, iv, data):
    aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
    aes = pyaes.Decrypter(aes_cbc)
    s = aes.feed(data) + aes.feed()  # empty aes.feed() strips pkcs padding
    return s

def encrypt_aes(secret, s):
    iv = bytes(os.urandom(16))
    ct = aes_encrypt_with_iv(secret, iv, s)
    e = iv + ct
    return e

def decrypt_aes(secret, e):
    iv, e = e[:16], e[16:]
    s = aes_decrypt_with_iv(secret, iv, e)
    return s

def sha256(x):
    return hashlib.sha256(x).digest()

def sha512(x):
    return hashlib.sha512(x).digest()

def double_hash(x):
    if type(x) is not bytearray:
        x = x.encode('utf-8')
    return sha256(sha256(x))

def derive_keys(x):
    h = double_hash(x)
    h = sha512(h)
    return (h[:len(h) // 2], h[len(h) // 2:])

def to_string(x, enc):
    if isinstance(x, (bytes, bytearray)):
        return x.decode(enc)
    if isinstance(x, str):
        return x
    else:
        raise DeviceFailureError("Not a string or bytes like object")

class BitboxSimulator():
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.connect((self.ip, self.port))
        self.socket.settimeout(1)

    def send_recv(self, msg):
        self.socket.sendall(msg)
        data = self.socket.recv(3584)
        return data

    def close(self):
        self.socket.close()

    def get_serial_number_string(self):
        return 'dbb_fw:v5.0.0'

def send_frame(data, device):
    data = bytearray(data)
    data_len = len(data)
    seq = 0
    idx = 0
    write = []
    while idx < data_len:
        if idx == 0:
            # INIT frame
            write = data[idx: idx + min(data_len, usb_report_size - 7)]
            device.write(b'\0' + struct.pack(">IBH", HWW_CID, HWW_CMD, data_len & 0xFFFF) + write + b'\xEE' * (usb_report_size - 7 - len(write)))
        else:
            # CONT frame
            write = data[idx: idx + min(data_len, usb_report_size - 5)]
            device.write(b'\0' + struct.pack(">IB", HWW_CID, seq) + write + b'\xEE' * (usb_report_size - 5 - len(write)))
            seq += 1
        idx += len(write)


def read_frame(device):
    # INIT response
    read = bytearray(device.read(usb_report_size))
    cid = ((read[0] * 256 + read[1]) * 256 + read[2]) * 256 + read[3]
    cmd = read[4]
    data_len = read[5] * 256 + read[6]
    data = read[7:]
    idx = len(read) - 7
    while idx < data_len:
        # CONT response
        read = bytearray(device.read(usb_report_size))
        data += read[5:]
        idx += len(read) - 5
    assert cid == HWW_CID, '- USB command ID mismatch'
    assert cmd == HWW_CMD, '- USB command frame mismatch'
    return data

def get_firmware_version(device):
    serial_number = device.get_serial_number_string()
    split_serial = serial_number.split(':')
    firm_ver = split_serial[1][1:] # Version is vX.Y.Z, we just need X.Y.Z
    split_ver = firm_ver.split('.')
    return (int(split_ver[0]), int(split_ver[1]), int(split_ver[2])) # major, minor, revision

def send_plain(msg, device):
    reply = ""
    try:
        if isinstance(device, BitboxSimulator):
            r = device.send_recv(msg)
        else:
            firm_ver = get_firmware_version(device)
            if (firm_ver[0] == 2 and firm_ver[1] == 0) or (firm_ver[0] == 1):
                hidBufSize = 4096
                device.write('\0' + msg + '\0' * (hidBufSize - len(msg)))
                r = bytearray()
                while len(r) < hidBufSize:
                    r += bytearray(device.read(hidBufSize))
            else:
                send_frame(msg, device)
                r = read_frame(device)
        r = r.rstrip(b' \t\r\n\0')
        r = r.replace(b"\0", b'')
        r = to_string(r, 'utf8')
        reply = json.loads(r)
    except Exception as e:
        reply = json.loads('{"error":"Exception caught while sending plaintext message to DigitalBitbox ' + str(e) + '"}')
    return reply

def send_encrypt(msg, password, device):
    reply = ""
    try:
        firm_ver = get_firmware_version(device)
        if firm_ver[0] >= 5:
            encryption_key, authentication_key = derive_keys(password)
            msg = encrypt_aes(encryption_key, msg)
            hmac_digest = hmac.new(authentication_key, msg, digestmod=hashlib.sha256).digest()
            authenticated_msg = base64.b64encode(msg + hmac_digest)
        else:
            encryption_key = double_hash(password)
            authenticated_msg = base64.b64encode(encrypt_aes(encryption_key, msg))
        reply = send_plain(authenticated_msg, device)
        if 'ciphertext' in reply:
            b64_unencoded = bytes(base64.b64decode(''.join(reply["ciphertext"])))
            if firm_ver[0] >= 5:
                msg = b64_unencoded[:-32]
                reply_hmac = b64_unencoded[-32:]
                hmac_calculated = hmac.new(authentication_key, msg, digestmod=hashlib.sha256).digest()
                if not hmac.compare_digest(reply_hmac, hmac_calculated):
                    raise Exception("Failed to validate HMAC")
            else:
                msg = b64_unencoded
            reply = decrypt_aes(encryption_key, msg)
            reply = json.loads(reply.decode("utf-8"))
        if 'error' in reply:
            password = None
    except Exception as e:
        reply = {'error': 'Exception caught while sending encrypted message to DigitalBitbox ' + str(e)}
    return reply

def stretch_backup_key(password):
    key = hashlib.pbkdf2_hmac('sha512', password.encode(), b'Digital Bitbox', 20480)
    return binascii.hexlify(key).decode()

def format_backup_filename(name):
    return '{}-{}.pdf'.format(name, time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime()))

# This class extends the HardwareWalletClient for Digital Bitbox specific things
class DigitalbitboxClient(HardwareWalletClient):

    def __init__(self, path, password, expert=False):
        super(DigitalbitboxClient, self).__init__(path, password, expert)
        if not password:
            raise NoPasswordError('Password must be supplied for digital BitBox')
        if path.startswith('udp:'):
            split_path = path.split(':')
            ip = split_path[1]
            port = int(split_path[2])
            self.device = BitboxSimulator(ip, port)
        else:
            self.device = hid.device()
            self.device.open_path(path.encode())
        self.password = password

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    @digitalbitbox_exception
    def get_pubkey_at_path(self, path):
        if '\'' not in path and 'h' not in path and 'H' not in path:
            raise BadArgumentError('The digital bitbox requires one part of the derivation path to be derived using hardened keys')
        reply = send_encrypt('{"xpub":"' + path + '"}', self.password, self.device)
        if 'error' in reply:
            raise DBBError(reply)

        if self.is_testnet:
            result = {'xpub': xpub_main_2_test(reply['xpub'])}
        else:
            result = {'xpub': reply['xpub']}
        if self.expert:
            xpub_obj = ExtendedKey()
            xpub_obj.deserialize(reply['xpub'])
            result.update(xpub_obj.get_printable_dict())
        return result

    # Must return a hex string with the signed transaction
    # The tx must be in the PSBT format
    @digitalbitbox_exception
    def sign_tx(self, tx):

        # Create a transaction with all scriptsigs blanekd out
        blank_tx = CTransaction(tx.tx)

        # Get the master key fingerprint
        master_fp = get_xpub_fingerprint(self.get_pubkey_at_path('m/0h')['xpub'])

        # create sighashes
        sighash_tuples = []
        for txin, psbt_in, i_num in zip(blank_tx.vin, tx.inputs, range(len(blank_tx.vin))):
            sighash = b""
            if psbt_in.non_witness_utxo:
                utxo = psbt_in.non_witness_utxo.vout[txin.prevout.n]

                # Check if P2SH
                if utxo.is_p2sh():
                    # Look up redeemscript
                    redeemscript = psbt_in.redeem_script
                    # Add to blank_tx
                    txin.scriptSig = redeemscript
                # Check if P2PKH
                elif utxo.is_p2pkh() or utxo.is_p2pk():
                    txin.scriptSig = psbt_in.non_witness_utxo.vout[txin.prevout.n].scriptPubKey
                # We don't know what this is, skip it
                else:
                    continue

                # Serialize and add sighash ALL
                ser_tx = blank_tx.serialize_without_witness()
                ser_tx += b"\x01\x00\x00\x00"

                # Hash it
                sighash += hash256(ser_tx)
                txin.scriptSig = b""
            elif psbt_in.witness_utxo:
                # Calculate hashPrevouts and hashSequence
                prevouts_preimage = b""
                sequence_preimage = b""
                for inputs in blank_tx.vin:
                    prevouts_preimage += inputs.prevout.serialize()
                    sequence_preimage += struct.pack("<I", inputs.nSequence)
                hashPrevouts = hash256(prevouts_preimage)
                hashSequence = hash256(sequence_preimage)

                # Calculate hashOutputs
                outputs_preimage = b""
                for output in blank_tx.vout:
                    outputs_preimage += output.serialize()
                hashOutputs = hash256(outputs_preimage)

                # Get the scriptCode
                scriptCode = b""
                witness_program = b""
                if psbt_in.witness_utxo.is_p2sh():
                    # Look up redeemscript
                    redeemscript = psbt_in.redeem_script
                    witness_program = redeemscript
                else:
                    witness_program = psbt_in.witness_utxo.scriptPubKey

                # Check if witness_program is script hash
                if len(witness_program) == 34 and witness_program[0] == 0x00 and witness_program[1] == 0x20:
                    # look up witnessscript and set as scriptCode
                    witnessscript = psbt_in.witness_script
                    scriptCode += ser_compact_size(len(witnessscript)) + witnessscript
                else:
                    scriptCode += b"\x19\x76\xa9\x14"
                    scriptCode += witness_program[2:]
                    scriptCode += b"\x88\xac"

                # Make sighash preimage
                preimage = b""
                preimage += struct.pack("<i", blank_tx.nVersion)
                preimage += hashPrevouts
                preimage += hashSequence
                preimage += txin.prevout.serialize()
                preimage += scriptCode
                preimage += struct.pack("<q", psbt_in.witness_utxo.nValue)
                preimage += struct.pack("<I", txin.nSequence)
                preimage += hashOutputs
                preimage += struct.pack("<I", tx.tx.nLockTime)
                preimage += b"\x01\x00\x00\x00"

                # hash it
                sighash = hash256(preimage)

            # Figure out which keypath thing is for this input
            for pubkey, keypath in psbt_in.hd_keypaths.items():
                if master_fp == keypath[0]:
                    # Add the keypath strings
                    keypath_str = 'm'
                    for index in keypath[1:]:
                        keypath_str += '/'
                        if index >= 0x80000000:
                            keypath_str += str(index - 0x80000000) + 'h'
                        else:
                            keypath_str += str(index)

                    # Create tuples and add to List
                    tup = (binascii.hexlify(sighash).decode(), keypath_str, i_num, pubkey)
                    sighash_tuples.append(tup)

        # Return early if nothing to do
        if len(sighash_tuples) == 0:
            return {'psbt': tx.serialize()}

        # Sign the sighashes
        to_send = '{"sign":{"data":['
        for tup in sighash_tuples:
            to_send += '{"hash":"'
            to_send += tup[0]
            to_send += '","keypath":"'
            to_send += tup[1]
            to_send += '"},'
        if to_send[-1] == ',':
            to_send = to_send[:-1]
        to_send += ']}}'
        logging.debug(to_send)

        reply = send_encrypt(to_send, self.password, self.device)
        logging.debug(reply)
        if 'error' in reply:
            raise DBBError(reply)
        print("Touch the device for 3 seconds to sign. Touch briefly to cancel", file=sys.stderr)
        reply = send_encrypt(to_send, self.password, self.device)
        logging.debug(reply)
        if 'error' in reply:
            raise DBBError(reply)

        # Extract sigs
        sigs = []
        for item in reply['sign']:
            sigs.append(binascii.unhexlify(item['sig']))

        # Make sigs der
        der_sigs = []
        for sig in sigs:
            der_sigs.append(ser_sig_der(sig[0:32], sig[32:64]))

        # add sigs to tx
        for tup, sig in zip(sighash_tuples, der_sigs):
            tx.inputs[tup[2]].partial_sigs[tup[3]] = sig

        return {'psbt': tx.serialize()}

    # Must return a base64 encoded string with the signed message
    # The message can be any string
    @digitalbitbox_exception
    def sign_message(self, message, keypath):
        to_hash = b""
        to_hash += self.message_magic
        to_hash += ser_compact_size(len(message))
        to_hash += message.encode()

        hashed_message = hash256(to_hash)

        to_send = '{"sign":{"data":[{"hash":"'
        to_send += binascii.hexlify(hashed_message).decode()
        to_send += '","keypath":"'
        to_send += keypath
        to_send += '"}]}}'

        reply = send_encrypt(to_send, self.password, self.device)
        logging.debug(reply)
        if 'error' in reply:
            raise DBBError(reply)
        print("Touch the device for 3 seconds to sign. Touch briefly to cancel", file=sys.stderr)
        reply = send_encrypt(to_send, self.password, self.device)
        logging.debug(reply)
        if 'error' in reply:
            raise DBBError(reply)

        sig = binascii.unhexlify(reply['sign'][0]['sig'])
        r = sig[0:32]
        s = sig[32:64]
        recid = binascii.unhexlify(reply['sign'][0]['recid'])
        compact_sig = ser_sig_compact(r, s, recid)
        logging.debug(binascii.hexlify(compact_sig))

        return {"signature": base64.b64encode(compact_sig).decode('utf-8')}

    # Display address of specified type on the device. Only supports single-key based addresses.
    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        raise UnavailableActionError('The Digital Bitbox does not have a screen to display addresses on')

    # Setup a new device
    @digitalbitbox_exception
    def setup_device(self, label='', passphrase=''):
        # Make sure this is not initialized
        reply = send_encrypt('{"device" : "info"}', self.password, self.device)
        if 'error' not in reply or ('error' in reply and (reply['error']['code'] != 101 and reply['error']['code'] != '101')):
            raise DeviceAlreadyInitError('Device is already initialized. Use wipe first and try again')

        # Need a wallet name and backup passphrase
        if not label or not passphrase:
            raise BadArgumentError('The label and backup passphrase for a new Digital Bitbox wallet must be specified and cannot be empty')

        # Set password
        to_send = {'password': self.password}
        reply = send_plain(json.dumps(to_send).encode(), self.device)

        # Now make the wallet
        key = stretch_backup_key(passphrase)
        backup_filename = format_backup_filename(label)
        to_send = {'seed': {'source': 'create', 'key': key, 'filename': backup_filename}}
        reply = send_encrypt(json.dumps(to_send).encode(), self.password, self.device)
        if 'error' in reply:
            return {'success': False, 'error': reply['error']['message']}
        return {'success': True}

    # Wipe this device
    @digitalbitbox_exception
    def wipe_device(self):
        reply = send_encrypt('{"reset" : "__ERASE__"}', self.password, self.device)
        if 'error' in reply:
            return {'success': False, 'error': reply['error']['message']}
        return {'success': True}

    # Restore device from mnemonic or xprv
    def restore_device(self, label='', word_count=24):
        raise UnavailableActionError('The Digital Bitbox does not support restoring via software')

    # Begin backup process
    @digitalbitbox_exception
    def backup_device(self, label='', passphrase=''):
        # Need a wallet name and backup passphrase
        if not label or not passphrase:
            raise BadArgumentError('The label and backup passphrase for a Digital Bitbox backup must be specified and cannot be empty')

        key = stretch_backup_key(passphrase)
        backup_filename = format_backup_filename(label)
        to_send = {'backup': {'source': 'all', 'key': key, 'filename': backup_filename}}
        reply = send_encrypt(json.dumps(to_send).encode(), self.password, self.device)
        if 'error' in reply:
            raise DBBError(reply)
        return {'success': True}

    # Close the device
    def close(self):
        self.device.close()

    # Prompt pin
    def prompt_pin(self):
        raise UnavailableActionError('The Digital Bitbox does not need a PIN sent from the host')

    # Send pin
    def send_pin(self, pin):
        raise UnavailableActionError('The Digital Bitbox does not need a PIN sent from the host')

    # Toggle passphrase
    def toggle_passphrase(self):
        raise UnavailableActionError('The Digital Bitbox does not support toggling passphrase from the host')

def enumerate(password=''):
    results = []
    devices = hid.enumerate(DBB_VENDOR_ID, DBB_DEVICE_ID)
    # Try connecting to simulator
    try:
        dev = BitboxSimulator('127.0.0.1', 35345)
        dev.send_recv(b'{"device" : "info"}')
        devices.append({'path': b'udp:127.0.0.1:35345', 'interface_number': 0})
        dev.close()
    except:
        pass
    for d in devices:
        if ('interface_number' in d and d['interface_number'] == 0
                or ('usage_page' in d and d['usage_page'] == 0xffff)):
            d_data = {}

            path = d['path'].decode()
            d_data['type'] = 'digitalbitbox'
            d_data['model'] = 'digitalbitbox_01'
            if path == 'udp:127.0.0.1:35345':
                d_data['model'] += '_simulator'
            d_data['path'] = path

            client = None
            with handle_errors(common_err_msgs["enumerate"], d_data):
                client = DigitalbitboxClient(path, password)

                # Check initialized
                reply = send_encrypt('{"device" : "info"}', password, client.device)
                if 'error' in reply and (reply['error']['code'] == 101 or reply['error']['code'] == '101'):
                    d_data['error'] = 'Not initialized'
                    d_data['code'] = DEVICE_NOT_INITIALIZED
                else:
                    d_data['fingerprint'] = client.get_master_fingerprint_hex()
                d_data['needs_pin_sent'] = False
                d_data['needs_passphrase_sent'] = True

            if client:
                client.close()

            results.append(d_data)
    return results
