#! /usr/bin/env python3

# Hardware wallet interaction script

import argparse
import hid
import json
import sys
import logging
import glob
import importlib

from .serializations import PSBT, Base64ToHex, HexToBase64, hash160
from .base58 import xpub_to_address, xpub_to_pub_hex, get_xpub_fingerprint_as_id, get_xpub_fingerprint_hex
from os.path import dirname, basename, isfile
from .hwwclient import NoPasswordError

# Error codes
NO_DEVICE_PATH = -1
NO_DEVICE_TYPE = -2
DEVICE_CONN_ERROR = -3
UNKNWON_DEVICE_TYPE = -4
INVALID_TX = -5
NO_PASSWORD = -6
BAD_ARGUMENT = -7

class UnknownDeviceError(Exception):
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

# Get the client for the device
def get_client(device_type, device_path, password=None):
    class_name = device_type.capitalize()
    module = device_type.lower()

    try:
        imported_dev = importlib.import_module('.devices.' + module, __package__)
        client_constructor = getattr(imported_dev, class_name + 'Client')
        client = client_constructor(device_path, password)
    except ImportError as e:
        raise UnknownDeviceError('Unknown device type specified')

    return client

# Get a list of all available hardware wallets
def enumerate(args):
    result = []

    # Gets the module names of all the files in devices/
    files = glob.glob(dirname(__file__)+"/devices/*.py")
    modules = [ basename(f)[:-3] for f in files if isfile(f) and not f.endswith('__init__.py')]

    for module in modules:
        try:
            imported_dev = importlib.import_module('.devices.' + module, __package__)
            result.extend(imported_dev.enumerate(args.password))
        except ImportError as e:
            pass # Ignore ImportErrors, the user may not have all device dependencies installed
    return result

# Fingerprint or device type required
def find_device(args):
    assert(args.device_path is None)
    devices = enumerate(args)
    for d in devices:
        if args.device_type is not None and d['type'] != args.device_type:
            continue
        try:
            client = get_client(d['type'], d['path'], args.password)
            master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
            master_fpr = get_xpub_fingerprint_hex(master_xpub)
            if args.fingerprint and master_fpr != args.fingerprint:
                client.close()
                continue
            else:
                return client
        except:
            pass # Ignore things we wouldn't get fingerprints for
    return None

def getmasterxpub(args, client):
    return client.get_master_xpub()

def signtx(args, client):
    # Deserialize the transaction
    try:
        tx = PSBT()
        tx.deserialize(args.psbt)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {'error':'You must provide a PSBT','code':INVALID_TX}
    return client.sign_tx(tx)

def getxpub(args, client):
    return client.get_pubkey_at_path(args.path)

def signmessage(args, client):
    return client.sign_message(args.message, args.path)

def getkeypool(args, client):
    # args[0]; start index (e.g. 0)
    # args[1]: end index (e.g. 1000)
    path = args.path
    start = args.start
    end = args.end
    internal = args.internal
    keypool = args.keypool
    account = args.account or 0

    if args.sh_wpkh == True and args.wpkh == True:
        return json.dumps({'error':'Both `--wpkh` and `--sh_wpkh` can not be selected at the same time.','code':BAD_ARGUMENT})

    master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
    master_fpr = get_xpub_fingerprint_as_id(master_xpub)

    if not path:
      # Master key:
      path = "m/"

      # Purpose
      if args.wpkh == True:
        path += "84'/"
      elif args.sh_wpkh == True:
        path += "49'/"
      else:
        path += "44'/"

      # Coin type
      if args.testnet == True:
        path += "1'/"
      else:
        path += "0'/"

      # Account
      path += str(account) + '\'/'

      # Receive or change
      if args.internal == True:
        path += "1/*"
      else:
        path += "0/*"
    else:
      if path[0] != "m":
        return {'error':'Path must start with m/','code':BAD_ARGUMENT}
      if path[-1] != "*":
        return {'error':'Path must end with /*','code':BAD_ARGUMENT}

    # Find the last hardened derivation:
    path = path.replace('\'','h')
    path_suffix = ''
    for component in path.split("/")[::-1]:
      if component[-1] == 'h' or component[-1] == 'm':
        break
      path_suffix = '/' + component + path_suffix
    path_base = path.rsplit(path_suffix)[0]

    # Get the key at the base
    base_key = client.get_pubkey_at_path(path_base)['xpub']

    import_data = []
    this_import = {}

    descriptor_open = 'pkh('
    descriptor_close = ')'
    if args.wpkh == True:
          descriptor_open = 'wpkh('
    elif args.sh_wpkh == True:
          descriptor_open = 'sh(wpkh('
          descriptor_close = '))'

    this_import['desc'] = descriptor_open + '[' + master_fpr + path_base.replace('m', '') + ']' + base_key + path_suffix + descriptor_close
    this_import['range'] = {'start': start, 'end': end}
    this_import['timestamp'] = 'now'
    this_import['internal'] = internal
    this_import['keypool'] = keypool
    import_data.append(this_import)
    return import_data

def displayaddress(args, client):
    if args.sh_wpkh == True and args.wpkh == True:
        return json.dumps({'error':'Both `--wpkh` and `--sh_wpkh` can not be selected at the same time.','code':BAD_ARGUMENT})
    return client.display_address(args.path, args.sh_wpkh, args.wpkh)

def process_commands(args):
    parser = argparse.ArgumentParser(description='Access and send commands to a hardware wallet device. Responses are in JSON format')
    parser.add_argument('--device-path', '-d', help='Specify the device path of the device to connect to')
    parser.add_argument('--device-type', '-t', help='Specify the type of device that will be connected. If `--device-path` not given, the first device of this type enumerated is used.')
    parser.add_argument('--password', '-p', help='Device password if it has one (e.g. DigitalBitbox)')
    parser.add_argument('--testnet', help='Use testnet prefixes', action='store_true')
    parser.add_argument('--debug', help='Print debug statements', action='store_true')
    parser.add_argument('--fingerprint', '-f', help='Specify the device to connect to using the first 4 bytes of the hash160 of the master public key. It will connect to the first device that matches this fingerprint.')

    subparsers = parser.add_subparsers(description='Commands', dest='command')
    # work-around to make subparser required
    subparsers.required = True

    enumerate_parser = subparsers.add_parser('enumerate', help='List all available devices')
    enumerate_parser.set_defaults(func=enumerate)

    getmasterxpub_parser = subparsers.add_parser('getmasterxpub', help='Get the extended public key at m/44\'/0\'/0\'')
    getmasterxpub_parser.set_defaults(func=getmasterxpub)

    signtx_parser = subparsers.add_parser('signtx', help='Sign a PSBT')
    signtx_parser.add_argument('psbt', help='The Partially Signed Bitcoin Transaction to sign')
    signtx_parser.set_defaults(func=signtx)

    getxpub_parser = subparsers.add_parser('getxpub', help='Get an extended public key')
    getxpub_parser.add_argument('path', help='The BIP 32 derivation path to derive the key at')
    getxpub_parser.set_defaults(func=getxpub)

    signmsg_parser = subparsers.add_parser('signmessage', help='Sign a message')
    signmsg_parser.add_argument('message', help='The message to sign')
    signmsg_parser.add_argument('path', help='The BIP 32 derivation path of the key to sign the message with')
    signmsg_parser.set_defaults(func=signmessage)

    getkeypool_parser = subparsers.add_parser('getkeypool', help='Get JSON array of keys that can be imported to Bitcoin Core with importmulti')
    getkeypool_parser.add_argument('--keypool', action='store_true', help='Indicates that the keys are to be imported to the keypool')
    getkeypool_parser.add_argument('--internal', action='store_true', help='Indicates that the keys are change keys')
    getkeypool_parser.add_argument('--sh_wpkh', action='store_true', help='Generate p2sh-nested segwit addresses (default path: m/49h/0h/0h/[0,1]/*)')
    getkeypool_parser.add_argument('--wpkh', action='store_true', help='Generate bech32 addresses (default path: m/84h/0h/0h/[0,1]/*)')
    getkeypool_parser.add_argument('--account', help='BIP43 account (default: 0)')
    getkeypool_parser.add_argument('--path', help='Derivation path, default follows BIP43 convention, e.g. m/84h/0h/0h/1/* with --wpkh --internal')
    getkeypool_parser.add_argument('start', type=int, help='The index to start at.')
    getkeypool_parser.add_argument('end', type=int, help='The index to end at.')
    getkeypool_parser.set_defaults(func=getkeypool)

    displayaddr_parser = subparsers.add_parser('displayaddress', help='Display an address')
    displayaddr_parser.add_argument('path', help='The BIP 32 derivation path of the key embedded in the address')
    displayaddr_parser.add_argument('--sh_wpkh', action='store_true', help='Display the p2sh-nested segwit address associated with this key path')
    displayaddr_parser.add_argument('--wpkh', action='store_true', help='Display the bech32 version of the address associated with this key path')
    displayaddr_parser.set_defaults(func=displayaddress)

    args = parser.parse_args(args)

    device_path = args.device_path
    device_type = args.device_type
    password = args.password
    command = args.command

    # Setup debug logging
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING)

    # List all available hardware wallet devices
    if command == 'enumerate':
        return args.func(args)

    # Auto detect if we are using fingerprint or type to identify device
    if args.fingerprint or (args.device_type and not args.device_path):
        client = find_device(args)
        if not client:
            return {'error':'Could not find device with specified fingerprint','code':DEVICE_CONN_ERROR}
    elif args.device_type and args.device_path:
        try:
            client = get_client(device_type, device_path, password)
        except NoPasswordError as e:
            return {'error':str(e),'code':NO_PASSWORD}
        except UnknownDeviceError as e:
            return {'error':str(e),'code':UNKNWON_DEVICE_TYPE}
        except Exception as e:
            return {'error':str(e),'code':DEVICE_CONN_ERROR}
    else:
        return {'error':'You must specify a device type or fingerprint for all commands except enumerate','code':NO_DEVICE_PATH}

    client.is_testnet = args.testnet

    # Do the commands
    result = args.func(args, client)

    # Close the device
    client.close()

    return result
