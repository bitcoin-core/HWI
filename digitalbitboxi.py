# Digital Bitbox interaction script

import hid
import struct
import json
import base64
import pyaes
import hashlib
import os
import binascii

from hwi import HardwareWalletClient
from serializations import CTransaction, PSBT, hash256, hash160, ser_sig_der, ser_sig_compact, ser_compact_size
from base58 import get_xpub_fingerprint, decode, to_address

applen = 225280 # flash size minus bootloader length
chunksize = 8*512
usb_report_size = 64 # firmware > v2.0
report_buf_size = 4096 # firmware v2.0.0
boot_buf_size_send = 4098
boot_buf_size_reply = 256
HWW_CID = 0xFF000000
HWW_CMD = 0x80 + 0x40 + 0x01


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


def EncodeAES(secret, s):
    iv = bytes(os.urandom(16))
    ct = aes_encrypt_with_iv(secret, iv, s)
    e = iv + ct
    return base64.b64encode(e)


def DecodeAES(secret, e):
    e = bytes(base64.b64decode(e))
    iv, e = e[:16], e[16:]
    s = aes_decrypt_with_iv(secret, iv, e)
    return s


def sha256(x):
    return hashlib.sha256(x).digest()


def Hash(x):
    if type(x) is unicode: x=x.encode('utf-8')
    return sha256(sha256(x))

def send_frame(data, device):
    data = bytearray(data)
    data_len = len(data)
    seq = 0;
    idx = 0;
    write = []
    while idx < data_len:
        if idx == 0:
            # INIT frame
            write = data[idx : idx + min(data_len, usb_report_size - 7)]
            device.write('\0' + struct.pack(">IBH",HWW_CID, HWW_CMD, data_len & 0xFFFF) + write + '\xEE' * (usb_report_size - 7 - len(write)))
        else:
            # CONT frame
            write = data[idx : idx + min(data_len, usb_report_size - 5)]
            device.write('\0' + struct.pack(">IB", HWW_CID, seq) + write + '\xEE' * (usb_report_size - 5 - len(write)))
            seq += 1
        idx += len(write)


def read_frame(device):
    # INIT response
    read = device.read(usb_report_size)
    cid = ((read[0] * 256 + read[1]) * 256 + read[2]) * 256 + read[3]
    cmd = read[4]
    data_len = read[5] * 256 + read[6]
    data = read[7:]
    idx = len(read) - 7;
    while idx < data_len:
        # CONT response
        read = device.read(usb_report_size)
        data += read[5:]
        idx += len(read) - 5
    assert cid == HWW_CID, '- USB command ID mismatch'
    assert cmd == HWW_CMD, '- USB command frame mismatch'
    return data

def send_plain(msg, device):
    reply = ""
    try:
        serial_number = device.get_serial_number_string()
        if serial_number == "dbb.fw:v2.0.0" or serial_number == "dbb.fw:v1.3.2" or serial_number == "dbb.fw:v1.3.1":
            device.write('\0' + bytearray(msg) + '\0' * (report_buf_size - len(msg)))
            r = []
            while len(r) < report_buf_size:
                r = r + device.read(report_buf_size)
        else:
            send_frame(msg, device)
            r = read_frame(device)
        r = str(bytearray(r)).rstrip(' \t\r\n\0')
        r = r.replace("\0", '')
        reply = json.loads(r)
    except Exception as e:
        reply = json.loads('{"error":"Exception caught while sending plaintext message to DigitalBitbox ' + str(e) + '"}')
    return reply

def send_encrypt(msg, password, device):
    reply = ""
    try:
        secret = Hash(password)
        msg = EncodeAES(secret, msg)
        reply = send_plain(msg, device)
        if 'ciphertext' in reply:
            reply = DecodeAES(secret, ''.join(reply["ciphertext"]))
            reply = json.loads(reply)
        if 'error' in reply:
            password = None
    except Exception as e:
        reply = {'error':'Exception caught while sending encrypted message to DigitalBitbox ' + str(e)}
    return reply

# This class extends the HardwareWalletClient for Digital Bitbox specific things
class DigitalBitboxClient(HardwareWalletClient):

    # device is an HID device that has already been opened.
    def __init__(self, device, password):
        super(DigitalBitboxClient, self).__init__(device)
        self.device = device
        self.password = password

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        reply = send_encrypt('{"xpub":"' + path + '"}', self.password, self.device)
        return json.dumps({'xpub':reply['xpub']})

    # Must return a hex string with the signed transaction
    # The tx must be in the PSBT format
    def sign_tx(self, tx):

        # Create a transaction with all scriptsigs blanekd out
        blank_tx = CTransaction(tx.tx)

        # Get the master key fingerprint
        master_fp = get_xpub_fingerprint(json.loads(self.get_pubkey_at_path('m/0'))['xpub'])

        # create sighashes
        sighash_tuples = []
        for txin, psbt_in, i_num in zip(blank_tx.vin, tx.inputs, range(len(blank_tx.vin))):
            sighash = b""
            pubkeys = []
            if psbt_in.non_witness_utxo:
                utxo = psbt_in.non_witness_utxo.vout[txin.prevout.n]

                # Check if P2SH
                if utxo.is_p2sh():
                    # Look up redeemscript
                    redeemscript = psbt_in.redeem_script
                    # Add to blank_tx
                    txin.scriptSig = redeemscript
                    # Find which pubkeys to sign with for this input
                    for pubkey in tx.hd_keypaths.keys():
                        if pubkey in redeemscript:
                            pubkeys.append(pubkey)
                # Check if P2PKH
                elif utxo.is_p2pkh() or utxo.is_p2pk():
                    txin.scriptSig = psbt_in.non_witness_utxo.vout[txin.prevout.n].scriptPubKey
                    # Find which pubkeys to sign with for this input
                    for pubkey in psbt_in.hd_keypaths.keys():
                        if utxo.is_p2pk() and pubkey in utxo.scriptPubKey:
                            pubkeys.append(pubkey)
                        if utxo.is_p2pkh and hash160(pubkey) in utxo.scriptPubKey:
                            pubkeys.append(pubkey)
                # We don't know what this is, skip it
                else:
                    continue

                # Serialize and add sighash ALL
                ser_tx = blank_tx.serialize_without_witness()
                ser_tx += b"\x01\x00\x00\x00"
                print(binascii.hexlify(ser_tx))

                # Hash it
                sighash += hash256(ser_tx)
                print(binascii.hexlify(sighash))
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
                    witness_program += redeemscript
                else:
                    witness_program += psbt_in.witness_utxo.scriptPubKey

                # Check if witness_program is script hash
                if len(witness_program) == 34 and witness_program[0] == OP_0 and witness_program[1] == 0x20:
                    # look up witnessscript and set as scriptCode
                    witnessscript = psbt_in.witness_script
                    scriptCode += ser_compact_size(len(witnessscript)) + witnessscript
                else:
                    scriptCode += b"\x19\x76\xa9\x14"
                    scriptCode += redeemscript[2:]
                    scriptCode += b"\x88\xac"

                # Find pubkeys to sign with in the scriptCode

                # Find which pubkeys to sign with for this input
                for pubkey in psbt_in.hd_keypaths.keys():
                    if hash160(pubkey) in scriptCode or pubkey in scriptCode:
                        pubkeys.append(pubkey)

                # Make sighash preimage
                preimage = b""
                preimage += struct.pack("<i", blank_tx.nVersion)
                preimage += hashPrevouts
                preimage += hashSequence
                preimage += txin.prevout.serialize()
                preimage += scriptCode
                preimage += psbt_in.witness_utxo.nValue
                preimage += txin.nSequence
                preimage += hashOutputs
                preimage += struct.pack("<I", tx.tx.nLockTime)
                preimage += b"\x01\x00\x00\x00"

                # hash it
                sighash += hash256(preimage)

            # Figure out which keypath thing is for this input
            for pubkey in pubkeys:
                keypath = tx.hd_keypaths[pubkey]
                print(master_fp)
                print(keypath[0])
                if master_fp == keypath[0]:
                    # Add the keypath strings
                    keypath_str = 'm/'
                    for index in keypath[1:]:
                        keypath_str += str(index) + "/"

                    # Create tuples and add to List
                    tup = (binascii.hexlify(sighash), keypath_str, i_num, pubkey)
                    sighash_tuples.append(tup)

        # Sign the sighashes
        to_send = '{"sign":{"data":['
        for tup in sighash_tuples:
            to_send += '{"hash":"'
            to_send += tup[0]
            to_send += '","keypath":"'
            to_send += tup[1]
            to_send += '"},'
        to_send = to_send[:-1]
        to_send += ']}}'
        print(to_send)

        reply = send_encrypt(to_send, self.password, self.device)
        print(reply)
        if 'error' in reply:
            return
        print("Touch the device for 3 seconds to sign. Touch briefly to cancel")
        reply = send_encrypt(to_send, self.password, self.device)
        print(reply)
        if 'error' in reply:
            return

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

        # For each input, finalize only p2pkh and p2pk
        for txin, psbt_in in zip(tx.tx.vin, tx.inputs):
            if psbt_in.non_witness_utxo:
                utxo = psbt_in.non_witness_utxo.vout[txin.prevout.n]
                if utxo.is_p2pkh:
                    txin.scriptSig = struct.pack("B", len(psbt_in.partial_sigs.values()[0])) + psbt_in.partial_sigs.values()[0] + struct.pack("B", len(psbt_in.partial_sigs.keys()[0])) + psbt_in.partial_sigs.keys()[0]
                elif utxo.is_p2pk:
                    txin.scriptSig = truct.pack("B", len(psbt_in.partial_sigs.values()[0])) + psbt_in.partial_sigs.values()[0]
                psbt_in.set_null()

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

        return tx.serialize()

    # Must return a base64 encoded string with the signed message
    # The message can be any string
    def sign_message(self, message, keypath):
        to_hash = b""
        to_hash += self.message_magic
        to_hash += ser_compact_size(len(message))
        to_hash += message

        hashed_message = hash256(to_hash)

        to_send = '{"sign":{"data":[{"hash":"'
        to_send += binascii.hexlify(hashed_message)
        to_send += '","keypath":"'
        to_send += keypath
        to_send += '"}]}}'

        reply = send_encrypt(to_send, self.password, self.device)
        print(reply)
        if 'error' in reply:
            return
        print("Touch the device for 3 seconds to sign. Touch briefly to cancel")
        reply = send_encrypt(to_send, self.password, self.device)
        print(reply)
        if 'error' in reply:
            return

        sig = binascii.unhexlify(reply['sign'][0]['sig'])
        r = sig[0:32]
        s = sig[32:64]
        recid = binascii.unhexlify(reply['sign'][0]['recid'])
        compact_sig = ser_sig_compact(r, s, recid)
        print(binascii.hexlify(compact_sig))

        return json.dumps({"signature":base64.b64encode(compact_sig)})

    # Setup a new device
    def setup_device(self):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

    # Wipe this device
    def wipe_device(self):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')
