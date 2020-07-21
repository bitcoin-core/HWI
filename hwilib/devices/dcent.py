import hid
import struct
import json
import base64
import os
import sys
import time
from io import BytesIO, BufferedReader

from .dcentlib.transport_usb import TransportUsb
from .dcentlib.transport import TransportRunner as Dcent
from .dcentlib.wam_error import WamException
from .dcentlib.protobuf import general_pb2 as ErrType

from ..hwwclient import HardwareWalletClient
from ..errors import (
    ActionCanceledError,
    BadArgumentError,
    DeviceFailureError,
    DeviceConnectionError,
    DeviceAlreadyInitError,
    DEVICE_NOT_INITIALIZED,
    DeviceNotReadyError,
    NoPasswordError,
    UnavailableActionError,
    common_err_msgs,
    handle_errors,
)
from ..serializations import (
    CTransaction,
    ExtendedKey,
    is_p2pk,
    is_p2pkh,
    is_p2sh,
    is_p2wpkh,
    is_p2wsh,
    is_witness,
    ser_compact_size,
    PSBT,
)
from ..base58 import (
    get_xpub_fingerprint,
    to_address,
    xpub_main_2_test,
)

from .. import bech32
import re 

IoTrust_VENDOR_ID = 0x2f48
IoTrust_DEVICE_ID = 0x2130

py_enumerate = enumerate # Need to use the enumerate built-in but there's another function already named that
# minimal checking of string keypath
def is_vaild_keypath(keypath):
    parts = re.split("/", keypath)
    if parts[0] != "m":
        return False
    # strip hardening chars
    for index in parts[1:]:
        index_int = re.sub('[hH\']', '', index)
        if not index_int.isdigit():
            return False
        if int(index_int) > 0x80000000:
            return False
    return True

def normalize_keypath(keypath):
    # # TODO: replace 'H' or 'h' to '''
    if keypath.find('H')>0:
        path = keypath.replace('H', '\'')
    elif keypath.find('h')>0:
        path = keypath.replace('h', '\'')
    else:
        path = keypath 
    return path

def dcent_exception(f):
    def func(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValueError as e:
            raise BadArgumentError(str(e))
        except WamException as e:
            e_code = e.get_code()
            if e_code == ErrType.user_cancel:
                raise ActionCanceledError('{} canceled'.format(f.__name__))
            elif isinstance(e_code, int):
                raise DeviceFailureError(e.get_msg())
            else:
                raise BadArgumentError('Bad argument:' + e.get_msg())
    return func

def getSegwitRawTx(amount, hash, scriptPubKey):
    rawtx = b"SEGWIT"
    rawtx += b'\xFF\x20'
    txid = hex(hash)
    if txid[:2]=="0x":
        txid = txid[2:]
    rawtx += bytes.fromhex(txid)[::-1]  # txid reverse
    rawtx += struct.pack("<Q", amount) 
    rawtx += ser_compact_size(len(scriptPubKey))
    rawtx += scriptPubKey
    return rawtx.hex()
class DcentClient(HardwareWalletClient):
  
    def __init__(self, path, password='', expert=False):
        super(DcentClient, self).__init__(path, password, expert)
        self.simulator = False
        self.device = hid.device()
        self.device.open_path(path.encode())
        self.transport = TransportUsb(self.device)

        # if it wasn't able to find a client, throw an error
        if not self.device:
            raise IOError("no Device")

        # self.password = password
        # self.type = 'Dcent'
    @dcent_exception
    def get_pubkey_at_path(self, path):
        if not is_vaild_keypath(path):
            raise BadArgumentError("Invalid keypath")

        normalized_path = normalize_keypath(path)
        resp = Dcent.getPubKey(self.transport, normalized_path)
        
        if self.is_testnet:
            result = {'xpub': xpub_main_2_test(resp)}
        else:
            result = {'xpub': resp}
        
        if self.expert:
            xpub_obj = ExtendedKey()
            xpub_obj.deserialize(resp)
            result.update(xpub_obj.get_printable_dict())
        return result

    @dcent_exception
    def sign_message(self, message, path):
        if not is_vaild_keypath(path):
            raise BadArgumentError("Invalid keypath")

        normalized_path = normalize_keypath(path)
        
        signature = Dcent.signMessage(self.transport, message, normalized_path)
        return {"signature": signature}
   
    # Setup a new device
    def setup_device(self, label='', passphrase=''):
        raise UnavailableActionError('The D\'CENT do not support software setup')

    # Wipe this device
    def wipe_device(self):
        raise UnavailableActionError('The D\'CENT do not support wiping via software')

    # Restore device from mnemonic or xprv
    def restore_device(self, label='', word_count=24):
        raise UnavailableActionError('The D\'CENT do not support restoring via software')

    # Begin backup process
    def backup_device(self, label='', passphrase=''):
        raise UnavailableActionError('The D\'CENT do not support creating a backup via software')
    
    # Must return a hex string with the signed transaction
    # The tx must be in the combined unsigned transaction format
    @dcent_exception
    def sign_tx(self, tx):
        
        xpub = self.get_pubkey_at_path("m/0h")["xpub"]
        master_fp = get_xpub_fingerprint(xpub)

        passes = 1
        p = 0
        while p < passes:
            # Prepare inputs
            inputs = []
            isTxToSegwit = False
            # D'CENT only support p2wpkh, p2pkh
            for input_num, (psbt_in, txin) in py_enumerate(list(zip(tx.inputs, tx.tx.vin))):
                # Set the input stuff
                input = {}
                input["seq"] = txin.nSequence
                input["vout"] = txin.prevout.n

                # Detrermine spend type
                scriptcode = b''
                utxo = None
                if psbt_in.witness_utxo:
                    utxo = psbt_in.witness_utxo
                if psbt_in.non_witness_utxo:
                    if txin.prevout.hash != psbt_in.non_witness_utxo.sha256:
                        raise BadArgumentError('Input {} has a non_witness_utxo with the wrong hash'.format(input_num))
                    utxo = psbt_in.non_witness_utxo.vout[txin.prevout.n]
                # 
                if utxo is None:
                    continue
                scriptcode = utxo.scriptPubKey

                # Check if P2SH
                p2sh = False
                if is_p2sh(scriptcode):
                    raise UnavailableActionError('The D\'CENT do not support p2sh input')
                

                # Check segwit
                is_wit, _, _ = is_witness(scriptcode)
                
                # 
                if is_wit:
                    isTxToSegwit = True
                    if p2sh:
                        continue
                    else:
                        if is_p2wsh(scriptcode):
                            raise UnavailableActionError('The D\'CENT do not support p2wsh input')
                        else:
                            input["type"] = "p2wpkh" 
                else: 
                    if p2sh:
                        continue
                    else:
                        if is_p2pkh(scriptcode):
                            input["type"] = "p2pkh"
                        else:
                            input["type"] = "p2pk"
                
                for key in psbt_in.hd_keypaths.keys():
                    keypath = psbt_in.hd_keypaths[key]
                    if keypath[0] == master_fp:
                        keypath_str = "m/"
                        for index in keypath[1:]:
                            hdpad = ""
                            if index & 0x80000000:
                                index = index & 0x7FFFFFFF
                                hdpad = "\'"
                            keypath_str += str(index) + hdpad + "/"
                        
                        keypath_str = keypath_str[:-1]
                        input["path"] = keypath_str
                    else:
                        raise UnavailableActionError('The D\'CENT do not support Non-wallet input')

                if is_wit:
                    # SEGWIT(prefix) | FF(pad) | 0x20 | TXID | AMOUNT(8) | ScriptLen(VarInt) | ScriptPubKey
                    input["rawtx"] = "0x" + getSegwitRawTx(utxo.nValue, txin.prevout.hash, scriptcode)
                else: 
                    input["rawtx"] = "0x" + CTransaction(psbt_in.non_witness_utxo).serialize_with_witness().hex()
                # append to inputs
                inputs.append(input)

            # address version byte
            if self.is_testnet:
                p2pkh_version = b'\x6f'
                p2sh_version = b'\xc4'
                bech32_hrp = 'tb'
            else:
                p2pkh_version = b'\x00'
                p2sh_version = b'\x05'
                bech32_hrp = 'bc'

            # prepare outputs
            outputs = []
            for i, out in py_enumerate(tx.tx.vout):
                txoutput = {}
                txoutput["value"] = out.nValue
                if out.is_p2pkh():
                    txoutput["address"] = to_address(out.scriptPubKey[3:23], p2pkh_version)
                    txoutput["type"] = "p2pkh"
                elif out.is_p2sh():
                    txoutput["address"] = to_address(out.scriptPubKey[2:22], p2sh_version)
                    txoutput["type"] = "p2sh"
                else:
                    wit, ver, prog = out.is_witness()
                    if wit:
                        txoutput["address"] = bech32.encode(bech32_hrp, ver, prog)
                        if len(prog) == 32:
                            txoutput["type"] = "p2wsh"
                        else:
                            txoutput["type"] = "p2wpkh"
                    else:
                        raise BadArgumentError("Output is not an address")
                
                # Add the derivation path for change, but only if there is exactly one derivation path
                psbt_out = tx.outputs[i]
                if len(psbt_out.hd_keypaths) == 1:
                    changeIsSet = False
                    for txout in outputs:
                        if txout["type"]=="change":
                            changeIsSet = True
                            break
                    if not changeIsSet:
                        _, keypath = next(iter(psbt_out.hd_keypaths.items()))
                        if keypath[0] == master_fp and len(keypath) > 2 and keypath[-2] == 1:
                            keypath_str = "m/"
                            for index in keypath[1:]:
                                hdpad = ""
                                if index & 0x80000000:
                                    index = index & 0x7FFFFFFF
                                    hdpad = "\'"
                                keypath_str += str(index) + hdpad + "/"
                            
                            keypath_str = keypath_str[:-1]
                            
                            if( not (txoutput["type"] == "p2wpkh" and isTxToSegwit == True) and
                                    not (txoutput["type"] == "p2pkh" and isTxToSegwit == False)):
                                raise BadArgumentError("Change address type mismatch.")
                            
                            txoutput["address"] = keypath_str
                            txoutput["type"] = "change"
                
                
                # append to outputs
                outputs.append(txoutput)
            
            resp = Dcent.getSignedTx(self.transport, inputs, outputs, tx.tx.nVersion, tx.tx.nLockTime, self.is_testnet, isTxToSegwit)
            
            c_tx = CTransaction()
            value_tx = BufferedReader(BytesIO(bytes.fromhex(resp)))
            c_tx.deserialize(value_tx)
            
            # Each input has one signature
            for input_num, (psbt_in, sigIn) in py_enumerate(list(zip(tx.inputs, c_tx.vin))):
                for pubkey in psbt_in.hd_keypaths.keys():
                    fp = psbt_in.hd_keypaths[pubkey][0]
                    if fp == master_fp and pubkey not in psbt_in.partial_sigs:
                        if len(sigIn.scriptSig):
                            psbt_in.partial_sigs[pubkey] = sigIn.scriptSig[1:sigIn.scriptSig[0]+1]
                        else:
                            witscr = c_tx.wit.vtxinwit[input_num].serialize()
                            psbt_in.partial_sigs[pubkey] = witscr[2:witscr[1]+2]
                    break
            
            p += 1
        return {'psbt': tx.serialize()}
    
    # The D'CENT does not allow you to display_address it via software. That is done on the device itself. 
    # The D'CENT do not display address on the device screen. Just return the address. Only supports single-key based addresses.
    @dcent_exception
    def display_address(self, keypath, p2sh_p2wpkh, bech32, redeem_script=None):
        if not is_vaild_keypath(keypath):
            raise BadArgumentError("Invalid keypath")
        if redeem_script is not None:
            raise BadArgumentError("The D'CENT do not support P2SH address")
        address = Dcent.getAddress(self.transport, keypath, bech32, self.is_testnet)
        return {'address': address} 

    # Close the device
    def close(self):
        self.device.close()


def enumerate(password=''):
    results = []
    devices = hid.enumerate(IoTrust_VENDOR_ID, IoTrust_DEVICE_ID)

    for d in devices:
        if ('interface_number' in d and d['interface_number'] == 0):
            d_data = {}
            
            path = d['path'].decode()
            d_data['type'] = 'dcent'
            d_data['model'] = 'dcenthardwarewallet'
            d_data['path'] = path
            d_data['needs_pin_sent'] = False
            d_data['needs_passphrase_sent'] = False

            client = None
            with handle_errors(common_err_msgs["enumerate"], d_data):
                try:
                    client = DcentClient(path)
                    d_data['fingerprint'] = client.get_master_fingerprint_hex()
                except RuntimeError as e:
                   raise e
            
            if client:
                client.close()

            results.append(d_data)
    return results
