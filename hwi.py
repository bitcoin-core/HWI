#! /usr/bin/env python3

# Hardware wallet interaction script

import argparse
import hid
import json

from device_ids import trezor_device_ids, keepkey_device_ids, ledger_device_ids,\
                        digitalbitbox_device_ids, coldcard_device_ids
from serializations import PSBT, Base64ToHex, HexToBase64, hash160
from base58 import xpub_to_address, xpub_to_pub_hex, get_xpub_fingerprint_as_id

# Error codes
NO_DEVICE_PATH = -1
NO_DEVICE_TYPE = -2
DEVICE_CONN_ERROR = -3
UNKNWON_DEVICE_TYPE = -4
INVALID_TX = -5
NO_PASSWORD = -6

# This is an abstract class that defines all of the methods that each Hardware
# wallet subclass must implement.
class HardwareWalletClient(object):

    # device is an HID device that has already been opened.
    def __init__(self, device):
        self.device = device
        self.message_magic = b"\x18Bitcoin Signed Message:\n"
        self.is_testnet = False

    # Get the master BIP 44 pubkey
    def get_master_xpub(self):
        return self.get_pubkey_at_path('m/44\'/0\'/0\'')

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

    # Must return a hex string with the signed transaction
    # The tx must be in the combined unsigned transaction format
    def sign_tx(self, tx):
        raise NotImplementedError('The HardwareWalletClient base class does not '
            'implement this method')

    # Must return a base64 encoded string with the signed message
    # The message can be any string. keypath is the bip 32 derivation path for the key to sign with
    def sign_message(self, message, keypath):
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

# Get a list of all available hardware wallets
def enumerate():
    result = []
    devices = hid.enumerate()
    for d in devices:
        # Get trezors
        if (d['vendor_id'], d['product_id']) in trezor_device_ids:
            result.append({'type':'trezor','path':d['path'].decode("utf-8"),
                'serial_number':d['serial_number']})
        # Get keepkeys
        elif (d['vendor_id'], d['product_id']) in keepkey_device_ids:
            result.append({'type':'keepkey', 'path':d['path'].decode("utf-8"),
                'serial_number':d['serial_number']})
        # Get ledgers
        elif (d['vendor_id'], d['product_id']) in ledger_device_ids:
            result.append({'type':'ledger', 'path':d['path'].decode("utf-8"),
                'serial_number':d['serial_number']})
        # Get DigitalBitboxes
        elif (d['vendor_id'], d['product_id']) in digitalbitbox_device_ids:
            result.append({'type':'digitalbitbox', 'path':d['path'].decode("utf-8"),
                'serial_number':d['serial_number']})
        # Get ColdCards
        elif (d['vendor_id'], d['product_id']) in coldcard_device_ids:
            result.append({'type':'coldcard', 'path':d['path'].decode("utf-8"),
                'serial_number':d['serial_number']})
    print(json.dumps(result))

def getmasterxpub(args, client):
    print(client.get_master_xpub())

def signtx(args, client):
    # Deserialize the transaction
    try:
        tx = PSBT()
        tx.deserialize(args.psbt)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(json.dumps({'error':'You must provide a PSBT','code':INVALID_TX}))
        return
    print(json.dumps(client.sign_tx(tx)))

def getxpub(args, client):
    print(client.get_pubkey_at_path(args.path))

def signmessage(args, client):
    print(client.sign_message(args.message, args.path))

def getkeypool(args, client):
    # args[0]: path base (e.g. m/44'/0'/0')
    # args[1]; start index (e.g. 0)
    # args[2]: end index (e.g. 1000)
    # args[3]: internal (e.g. False)
    path_base = args.path_base
    start = args.start
    end = args.end
    internal = args.internal

    master_xpub = json.loads(client.get_pubkey_at_path('m/0h'))['xpub']
    master_fpr = get_xpub_fingerprint_as_id(master_xpub)

    import_data = []
    for i in range(start, end + 1):
        this_import = {}
        if (path_base[-1] == '/'):
            path = path_base + str(i)
        else:
            path = path_base + '/' + str(i)
        xpub = json.loads(client.get_pubkey_at_path(path))['xpub']
        address = xpub_to_address(xpub, args.testnet)
        this_import['scriptPubKey'] = {'address' : address}
        this_import['pubkeys'] = [{xpub_to_pub_hex(xpub) : {master_fpr : path.replace('\'', 'h')}}]
        this_import['timestamp'] = 'now'
        this_import['internal'] = internal
        import_data.append(this_import)
    print(json.dumps(import_data))

def process_commands():
    parser = argparse.ArgumentParser(description='Access and send commands to a hardware wallet device. Responses are in JSON format')
    parser.add_argument('--device-path', '-d', help='Specify the device path of the device to connect to')
    parser.add_argument('--device-type', '-t', help='Specify the type of device that will be connected')
    parser.add_argument('--password', '-p', help='Device password if it has one (e.g. DigitalBitbox)')
    parser.add_argument('--testnet', help='Use testnet prefixes', action='store_true')

    subparsers = parser.add_subparsers(description='Commands', dest='command')

    enumerate_parser = subparsers.add_parser('enumerate', help='List all available devices')
    enumerate_parser.set_defaults(func=enumerate)

    getmasterxpub_parser = subparsers.add_parser('getmasterxpub', help='Get the extended public key at m/44\'/0\'/0\'')
    getmasterxpub_parser.set_defaults(func=getmasterxpub)

    signtx_parser = subparsers.add_parser('signtx', help='Sign a PSBT')
    signtx_parser.add_argument('psbt', help='The Partially Signed Bitcoin Transaction to sign')
    signtx_parser.set_defaults(func=signtx)

    getxpub_parser = subparsers.add_parser('getxpub', help='Get an extended public key')
    getxpub_parser.add_argument('path', help='The BIP 32 derivation path to derive the key at')
    getmasterxpub_parser.set_defaults(func=getxpub)

    signmsg_parser = subparsers.add_parser('signmessage', help='Sign a message')
    signmsg_parser.add_argument('message', help='The message to sign')
    signmsg_parser.add_argument('path', help='The BIP 32 derivation path of the key to sign the message with')
    signmsg_parser.set_defaults(func=signmessage)

    getkeypol_parser = subparsers.add_parser('getkeypool', help='Get JSON array of keys that can be imported to Bitcoin Core with importmulti')
    getkeypol_parser.add_argument('--internal', action='store_true', help='Indicates that the keys are change keys')
    getkeypol_parser.add_argument('path_base', help='The prefix of the derivation path')
    getkeypol_parser.add_argument('start', type=int, help='The index to start at. The first key will be <path_base>/<start>')
    getkeypol_parser.add_argument('end', type=int, help='The index to end at. The last key will be <path_base>/<end>')
    getkeypol_parser.set_defaults(func=getkeypool)

    args = parser.parse_args()

    device_path = args.device_path
    device_type = args.device_type
    password = args.password
    command = args.command

    # List all available hardware wallet devices
    if command == 'enumerate':
        args.func()
        return

    if device_path is None:
        result = {'error':'You must specify a device path for all commands except enumerate','code':NO_DEVICE_PATH}
        print(json.dumps(result))
        return
    if device_type is None:
        result = {'error':'You must specify a device type for all commands except enumerate','code':NO_DEVICE_TYPE}
        print(json.dumps(result))
        return

    # Open the device
    try:
        device = hid.device()
        device_path = bytes(device_path.encode())
        device.open_path(device_path)
    except Exception as e:
        print(e)
        result = {'error':'Unable to connect to specified device','code':DEVICE_CONN_ERROR}
        print(json.dumps(result))
        return

    # Make a client
    if device_type == 'trezor':
        import trezori
        client = trezori.TrezorClient(device=device, path=device_path)
    elif device_type == 'keepkey':
        import keepkeyi
        client = keepkeyi.KeepKeyClient(device=device, path=device_path)
    elif device_type == 'ledger':
        # hack to use btchip-python's getDongle pipeline
        device.close()
        import ledgeri
        client = ledgeri.LedgerClient(device=device)
    elif device_type == 'digitalbitbox':
        if not password:
            result = {'error':'Password must be supplied for digital BitBox','code':NO_PASSWORD}
            print(json.dumps(result))
            return
        import digitalbitboxi
        client = digitalbitboxi.DigitalBitboxClient(device=device, password=password)
    elif device_type == 'coldcard':
        import coldcardi
        client = coldcardi.ColdCardClient(device=device)
    else:
        result = {'error':'Unknown device type specified','code':UNKNWON_DEVICE_TYPE}
        print(json.dumps(result))
        return
    client.is_testnet = args.testnet

    # Do the commands
    args.func(args, client)

    # Close the device
    device.close()


if __name__ == '__main__':
    process_commands()
