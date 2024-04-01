"""
BitBox01
********
"""

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
from functools import wraps
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
)

from ..common import (
    AddressType,
    Chain,
    hash256,
)
from ..descriptor import MultisigDescriptor
from ..hwwclient import HardwareWalletClient
from ..errors import (
    ActionCanceledError,
    BadArgumentError,
    DeviceFailureError,
    DeviceAlreadyInitError,
    DEVICE_NOT_INITIALIZED,
    DeviceNotReadyError,
    NoPasswordError,
    UnavailableActionError,
    common_err_msgs,
    handle_errors,
)
from ..key import (
    ExtendedKey,
)
from .._script import (
    is_p2pk,
    is_p2pkh,
    is_p2sh,
    is_p2wpkh,
    is_p2wsh,
    is_witness,
)
from ..psbt import PSBT
from .._serialize import (
    ser_sig_der,
    ser_sig_compact,
    ser_string,
    ser_compact_size,
)

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
bad_args: List[Union[int, str]] = [
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

device_failures: List[Union[int, str]] = [
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

cancels: List[Union[int, str]] = [
    600, # Aborted by user.
    601, # Touchbutton timed out.
]

cancels.extend([str(x) for x in cancels])

ERR_MEM_SETUP = 503 # Device initialization in progress.

class DBBError(Exception):
    def __init__(self, error: Dict[str, Dict[str, Union[str, int]]]) -> None:
        Exception.__init__(self)
        self.error = error

    def get_error(self) -> str:
        assert isinstance(self.error["error"]["message"], str)
        return self.error['error']['message']

    def get_code(self) -> Union[str, int]:
        assert isinstance(self.error["error"]["code"], int) or isinstance(self.error["error"]["code"], str)
        return self.error['error']['code']

    def __str__(self) -> str:
        return 'Error: {}, Code: {}'.format(self.error['error']['message'], self.error['error']['code'])

def digitalbitbox_exception(f: Callable[..., Any]) -> Any:
    @wraps(f)
    def func(*args: Any, **kwargs: Any) -> Any:
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

def aes_encrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
    aes = pyaes.Encrypter(aes_cbc)
    e = aes.feed(data) + aes.feed()  # empty aes.feed() appends pkcs padding
    assert isinstance(e, bytes)
    return e


def aes_decrypt_with_iv(key: bytes, iv: bytes, data: bytes) -> bytes:
    aes_cbc = pyaes.AESModeOfOperationCBC(key, iv=iv)
    aes = pyaes.Decrypter(aes_cbc)
    s = aes.feed(data) + aes.feed()  # empty aes.feed() strips pkcs padding
    assert isinstance(s, bytes)
    return s

def encrypt_aes(secret: bytes, s: bytes) -> bytes:
    iv = bytes(os.urandom(16))
    ct = aes_encrypt_with_iv(secret, iv, s)
    e = iv + ct
    return e

def decrypt_aes(secret: bytes, e: bytes) -> bytes:
    iv, e = e[:16], e[16:]
    s = aes_decrypt_with_iv(secret, iv, e)
    return s

def sha512(x: bytes) -> bytes:
    return hashlib.sha512(x).digest()

def double_hash(x: Union[str, bytes]) -> bytes:
    if not isinstance(x, bytes):
        x = x.encode('utf-8')
    return hash256(x)

def derive_keys(x: str) -> Tuple[bytes, bytes]:
    h = double_hash(x)
    h = sha512(h)
    return (h[:len(h) // 2], h[len(h) // 2:])

def to_string(x: Union[str, bytes, bytearray], enc: str) -> str:
    if isinstance(x, (bytes, bytearray)):
        return x.decode(enc)
    if isinstance(x, str):
        return x
    else:
        raise DeviceFailureError("Not a string or bytes like object")

class BitboxSimulator():
    def __init__(self, ip: str, port: int) -> None:
        self.ip = ip
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.connect((self.ip, self.port))
        self.socket.settimeout(1)

    def send_recv(self, msg: bytes) -> bytes:
        self.socket.sendall(msg)
        data = self.socket.recv(3584)
        return data

    def close(self) -> None:
        self.socket.close()

    def get_serial_number_string(self) -> str:
        return 'dbb_fw:v5.0.0'

Device = Union[BitboxSimulator, hid.device]

def send_frame(data: bytes, device: hid.device) -> None:
    data = bytearray(data)
    data_len = len(data)
    seq = 0
    idx = 0
    write = b""
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


def read_frame(device: hid.device) -> bytes:
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

def get_firmware_version(device: Device) -> Tuple[int, int, int]:
    serial_number = device.get_serial_number_string()
    split_serial = serial_number.split(':')
    firm_ver = split_serial[1][1:] # Version is vX.Y.Z, we just need X.Y.Z
    split_ver = firm_ver.split('.')
    return (int(split_ver[0]), int(split_ver[1]), int(split_ver[2])) # major, minor, revision

def send_plain(msg: bytes, device: Device) -> Dict[str, Any]:
    try:
        if isinstance(device, BitboxSimulator):
            r = device.send_recv(msg)
        else:
            firm_ver = get_firmware_version(device)
            if (firm_ver[0] == 2 and firm_ver[1] == 0) or (firm_ver[0] == 1):
                hidBufSize = 4096
                device.write(b"\0" + msg + b"\0" * (hidBufSize - len(msg)))
                r = bytearray()
                while len(r) < hidBufSize:
                    r += bytearray(device.read(hidBufSize))
            else:
                send_frame(msg, device)
                r = read_frame(device)
        r = r.rstrip(b' \t\r\n\0')
        r = r.replace(b"\0", b'')
        result = json.loads(to_string(r, "utf8"))
        assert isinstance(result, dict)
        return result
    except Exception as e:
        return {"error": f"Exception caught while sending plaintext message to DigitalBitbox {str(e)}"}

def send_encrypt(message: str, password: str, device: Device) -> Dict[str, Any]:
    msg = message.encode("utf8")
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
            plaintext = decrypt_aes(encryption_key, msg)
            result = json.loads(plaintext.decode("utf-8"))
            assert isinstance(result, dict)
            return result
        else:
            return reply
    except Exception as e:
        return {'error': 'Exception caught while sending encrypted message to DigitalBitbox ' + str(e)}

def stretch_backup_key(password: str) -> str:
    key = hashlib.pbkdf2_hmac('sha512', password.encode(), b'Digital Bitbox', 20480)
    return binascii.hexlify(key).decode()

def format_backup_filename(name: str) -> str:
    return '{}-{}.pdf'.format(name, time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime()))

# This class extends the HardwareWalletClient for Digital Bitbox specific things
class DigitalbitboxClient(HardwareWalletClient):

    def __init__(self, path: str, password: Optional[str], expert: bool = False, chain: Chain = Chain.MAIN) -> None:
        """
        The `DigitalbitboxClient` is a `HardwareWalletClient` for interacting with BitBox01 devices (previously known as the Digital BitBox).

        :param path: Path to the device as given by `enumerate`
        :param password: The password required to communicate with the device. Must be provided.
        :param expert: Whether to be in expert mode and return additional information.
        """
        if password is None:
            raise NoPasswordError('Password must be supplied for digital BitBox')
        super(DigitalbitboxClient, self).__init__(path, password, expert, chain)
        if path.startswith('udp:'):
            split_path = path.split(':')
            ip = split_path[1]
            port = int(split_path[2])
            self.device: Device = BitboxSimulator(ip, port)
        else:
            self.device = hid.device()
            self.device.open_path(path.encode())
        self.password: str = password

    @digitalbitbox_exception
    def get_pubkey_at_path(self, path: str) -> ExtendedKey:
        """
        Retrieve the public key at the path.
        The BitBox01 requires that at least one of the levels in the path is hardened.

        :param path: Path to retrieve the public key at.
        """
        if '\'' not in path and 'h' not in path and 'H' not in path:
            raise BadArgumentError('The digital bitbox requires one part of the derivation path to be derived using hardened keys')
        reply = send_encrypt('{"xpub":"' + path + '"}', self.password, self.device)
        if 'error' in reply:
            raise DBBError(reply)

        xpub = ExtendedKey.deserialize(reply["xpub"])
        if self.chain != Chain.MAIN:
            xpub.version = ExtendedKey.TESTNET_PUBLIC
        return xpub

    @digitalbitbox_exception
    def sign_tx(self, tx: PSBT) -> PSBT:

        # Create a transaction with all scriptsigs blanked out
        blank_tx = tx.get_unsigned_tx()

        # Get the master key fingerprint
        master_fp = self.get_master_fingerprint()

        # create sighashes
        sighash_tuples = []
        for txin, psbt_in, i_num in zip(blank_tx.vin, tx.inputs, range(len(blank_tx.vin))):
            sighash = b""
            utxo = None
            if psbt_in.witness_utxo:
                utxo = psbt_in.witness_utxo
            if psbt_in.non_witness_utxo:
                if txin.prevout.hash != psbt_in.non_witness_utxo.sha256:
                    raise BadArgumentError('Input {} has a non_witness_utxo with the wrong hash'.format(i_num))
                utxo = psbt_in.non_witness_utxo.vout[txin.prevout.n]
            if utxo is None:
                continue
            scriptcode = utxo.scriptPubKey

            # Check if P2SH
            p2sh = False
            if is_p2sh(scriptcode):
                # Look up redeemscript
                if len(psbt_in.redeem_script) == 0:
                    continue
                scriptcode = psbt_in.redeem_script
                p2sh = True

            is_wit, _, _ = is_witness(scriptcode)

            # Check if P2WSH
            if is_p2wsh(scriptcode):
                # Look up witnessscript
                if len(psbt_in.witness_script) == 0:
                    continue
                scriptcode = psbt_in.witness_script

            if not is_wit:
                if p2sh or is_p2pkh(scriptcode) or is_p2pk(scriptcode):
                    # Add to blank_tx
                    txin.scriptSig = scriptcode
                # We don't know what this is, skip it
                else:
                    continue

                # Serialize and add sighash ALL
                ser_tx = blank_tx.serialize_without_witness()
                ser_tx += b"\x01\x00\x00\x00"

                # Hash it
                sighash += hash256(ser_tx)
                txin.scriptSig = b""
            else:
                assert psbt_in.witness_utxo is not None
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

                # Check if scriptcode is p2wpkh
                if is_p2wpkh(scriptcode):
                    _, _, wit_prog = is_witness(scriptcode)
                    scriptcode = b"\x76\xa9\x14" + wit_prog + b"\x88\xac"

                # Make sighash preimage
                preimage = b""
                preimage += struct.pack("<i", blank_tx.nVersion)
                preimage += hashPrevouts
                preimage += hashSequence
                preimage += txin.prevout.serialize()
                preimage += ser_string(scriptcode)
                preimage += struct.pack("<q", psbt_in.witness_utxo.nValue)
                preimage += struct.pack("<I", txin.nSequence)
                preimage += hashOutputs
                preimage += struct.pack("<I", blank_tx.nLockTime)
                preimage += b"\x01\x00\x00\x00"

                # hash it
                sighash = hash256(preimage)

            # Figure out which keypath thing is for this input
            for pubkey, keypath in psbt_in.hd_keypaths.items():
                if master_fp == keypath.fingerprint:
                    # Add the keypath strings
                    keypath_str = keypath.get_derivation_path()

                    # Create tuples and add to List
                    tup = (binascii.hexlify(sighash).decode(), keypath_str, i_num, pubkey)
                    sighash_tuples.append(tup)

        # Return early if nothing to do
        if len(sighash_tuples) == 0:
            return tx

        for i in range(0, len(sighash_tuples), 15):
            tups = sighash_tuples[i:i + 15]

            # Sign the sighashes
            to_send = '{"sign":{"data":['
            for tup in tups:
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
            for tup, sig in zip(tups, der_sigs):
                tx.inputs[tup[2]].partial_sigs[tup[3]] = sig

        return tx

    @digitalbitbox_exception
    def sign_message(self, message: Union[str, bytes], keypath: str) -> str:
        to_hash = b""
        to_hash += self.message_magic
        to_hash += ser_compact_size(len(message))
        if isinstance(message, bytes):
            to_hash += message
        else:
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

        return base64.b64encode(compact_sig).decode('utf-8')

    def display_singlesig_address(self, keypath: str, addr_type: AddressType) -> str:
        """
        The BitBox01 does not have a screen to display addresses on.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Digital Bitbox does not have a screen to display addresses on')

    def display_multisig_address(self, addr_type: AddressType, multisig: MultisigDescriptor) -> str:
        """
        The BitBox01 does not have a screen to display addresses on.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Digital Bitbox does not have a screen to display addresses on')

    @digitalbitbox_exception
    def setup_device(self, label: str = "", passphrase: str = "") -> bool:
        # Make sure this is not initialized
        reply = send_encrypt('{"device" : "info"}', self.password, self.device)
        if 'error' not in reply or ('error' in reply and (reply['error']['code'] != 101 and reply['error']['code'] != '101')):
            raise DeviceAlreadyInitError('Device is already initialized. Use wipe first and try again')

        # Need a wallet name and backup passphrase
        if not label or not passphrase:
            raise BadArgumentError('The label and backup passphrase for a new Digital Bitbox wallet must be specified and cannot be empty')

        # Set password
        to_send: Dict[str, Any] = {'password': self.password}
        reply = send_plain(json.dumps(to_send).encode(), self.device)

        # Now make the wallet
        key = stretch_backup_key(passphrase)
        backup_filename = format_backup_filename(label)
        to_send = {'seed': {'source': 'create', 'key': key, 'filename': backup_filename}}
        reply = send_encrypt(json.dumps(to_send), self.password, self.device)
        if 'error' in reply:
            raise DeviceFailureError(reply['error']['message'])
        return True

    @digitalbitbox_exception
    def wipe_device(self) -> bool:
        reply = send_encrypt('{"reset" : "__ERASE__"}', self.password, self.device)
        if 'error' in reply:
            raise DeviceFailureError(reply["error"]["message"])
        return True

    def restore_device(self, label: str = "", word_count: int = 24) -> bool:
        """
        The BitBox01 does not support restoring via software.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Digital Bitbox does not support restoring via software')

    @digitalbitbox_exception
    def backup_device(self, label: str = "", passphrase: str = "") -> bool:
        # Need a wallet name and backup passphrase
        if not label or not passphrase:
            raise BadArgumentError('The label and backup passphrase for a Digital Bitbox backup must be specified and cannot be empty')

        key = stretch_backup_key(passphrase)
        backup_filename = format_backup_filename(label)
        to_send = {'backup': {'source': 'all', 'key': key, 'filename': backup_filename}}
        reply = send_encrypt(json.dumps(to_send), self.password, self.device)
        if 'error' in reply:
            raise DBBError(reply)
        return True

    def close(self) -> None:
        self.device.close()

    def prompt_pin(self) -> bool:
        """
        The BitBox01 does not need a PIN sent from the host.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Digital Bitbox does not need a PIN sent from the host')

    def send_pin(self, pin: str) -> bool:
        """
        The BitBox01 does not need a PIN sent from the host.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Digital Bitbox does not need a PIN sent from the host')

    def toggle_passphrase(self) -> bool:
        """
        The BitBox01 does not support toggling passphrase from the host.

        :raises UnavailableActionError: Always, this function is unavailable
        """
        raise UnavailableActionError('The Digital Bitbox does not support toggling passphrase from the host')

    def can_sign_taproot(self) -> bool:
        """
        The BitBox01 does not support Taproot as it is no longer supported by the manufacturer

        :returns: False, always
        """
        return False


def enumerate(password: Optional[str] = None, expert: bool = False, chain: Chain = Chain.MAIN, allow_emulators: bool = False) -> List[Dict[str, Any]]:
    results = []
    devices = hid.enumerate(DBB_VENDOR_ID, DBB_DEVICE_ID)
    # Try connecting to simulator
    if allow_emulators:
        try:
            dev = BitboxSimulator('127.0.0.1', 35345)
            dev.send_recv(b'{"device" : "info"}')
            devices.append({'path': b'udp:127.0.0.1:35345', 'interface_number': 0})
            dev.close()
        except Exception:
            pass
    for d in devices:
        if ('interface_number' in d and d['interface_number'] == 0
                or ('usage_page' in d and d['usage_page'] == 0xffff)):
            d_data: Dict[str, Any] = {}

            path = d['path'].decode()
            d_data['type'] = 'digitalbitbox'
            d_data['model'] = 'digitalbitbox_01'
            d_data['label'] = None
            if path == 'udp:127.0.0.1:35345':
                d_data['model'] += '_simulator'
            d_data['path'] = path

            client = None
            with handle_errors(common_err_msgs["enumerate"], d_data):
                client = DigitalbitboxClient(path, password)

                # Check initialized
                reply = send_encrypt('{"device" : "info"}', "" if password is None else password, client.device)
                if 'error' in reply and (reply['error']['code'] == 101 or reply['error']['code'] == '101'):
                    d_data['error'] = 'Not initialized'
                    d_data['code'] = DEVICE_NOT_INITIALIZED
                else:
                    d_data['fingerprint'] = client.get_master_fingerprint().hex()
                d_data['needs_pin_sent'] = False
                d_data['needs_passphrase_sent'] = True

            if client:
                client.close()

            results.append(d_data)
    return results
