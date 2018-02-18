# Hardware wallet interaction script

import argparse
import hid
import json

from device_ids import trezor_device_ids, keepkey_device_ids, ledger_device_ids,\
                        digitalbitbox_device_ids
from serializations import PSBT

# Error codes
NO_DEVICE_PATH = -1
NO_DEVICE_TYPE = -2
DEVICE_CONN_ERROR = -3
UNKNWON_DEVICE_TYPE = -4
INVALID_TX = -5

# This is an abstract class that defines all of the methods that each Hardware
# wallet subclass must implement.
class HardwareWalletClient(object):

    # device is an HID device that has already been opened.
    def __init__(self, device):
        self.device = device
        self.message_magic = b"\x18Bitcoin Signed Message:\n"

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
    return result

def process_commands(command, command_args, device_path, device_type):

    # List all available hardware wallet devices
    if command == 'enumerate':
        print(json.dumps(enumerate()))
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
        import digitalbitboxi
        client = digitalbitboxi.DigitalBitboxClient(device=device, password='asdfasdf')
    else:
        result = {'error':'Unknown device type specified','code':UNKNWON_DEVICE_TYPE}
        print(json.dumps(result))
        exit

    # Do the commands
    if command == 'getmasterxpub':
        print(client.get_master_xpub())

    elif command == 'signtx':
        # Deserialize the transaction
        try:
            tx = PSBT()
            tx.deserialize(command_args[0])
            print(json.dumps(client.sign_tx(tx)))
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(json.dumps({'error':'You must provide a PSBT','code':INVALID_TX}))
            exit

    elif command == 'getxpub':
        print(client.get_pubkey_at_path(command_args[0]))
    elif command == 'signmessage':
        print(client.sign_message(command_args[0], command_args[1]))
    else:
        print(json.dumps({'error':'Unknown command'}))

    # Close the device
    device.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Access and send commands to a hardware wallet device. Responses are in JSON format')
    parser.add_argument('--device-path', '-d', help='Specify the device path of the device to connect to')
    parser.add_argument('--device-type', '-t', help='Specify the type of device that will be connected')
    parser.add_argument('command', help='The action to do')
    parser.add_argument('args', help='Arguments for the command', nargs='*')

    args = parser.parse_args()
    command = args.command
    device_path = args.device_path
    device_type = args.device_type
    command_args = args.args

    process_commands(command, command_args, device_path, device_type)
