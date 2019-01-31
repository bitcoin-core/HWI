#! /usr/bin/env python3

from .commands import backup_device, displayaddress, enumerate, find_device, \
    get_client, getmasterxpub, getxpub, getkeypool, prompt_pin, restore_device, send_pin, setup_device, \
    signmessage, signtx, wipe_device
from .errors import (
    HWWError,
    NO_DEVICE_PATH,
    DEVICE_CONN_ERROR,
    NO_PASSWORD,
    UNKNWON_DEVICE_TYPE
)

import argparse
import getpass
import logging
import json
import sys

def backup_device_handler(args, client):
    return backup_device(client, label=args.label, backup_passphrase=args.backup_passphrase)

def displayaddress_handler(args, client):
    return displayaddress(client, path=args.path, sh_wpkh=args.sh_wpkh, wpkh=args.wpkh)

def enumerate_handler(args):
    return enumerate(password=args.password)

def getmasterxpub_handler(args, client):
    return getmasterxpub(client)

def getxpub_handler(args, client):
    return getxpub(client, path=args.path)

def getkeypool_handler(args, client):
    return getkeypool(client, path=args.path, start=args.start, end=args.end, internal=args.internal, keypool=args.keypool, account=args.account, sh_wpkh=args.sh_wpkh, wpkh=args.wpkh)

def restore_device_handler(args, client):
    return restore_device(client, label=args.label)

def setup_device_handler(args, client):
    return setup_device(client, label=args.label, backup_passphrase=args.backup_passphrase)

def signmessage_handler(args, client):
    return signmessage(client, message=args.message, path=args.path)

def signtx_handler(args, client):
    return signtx(client, psbt=args.psbt)

def wipe_device_handler(args, client):
    return wipe_device(client)

def prompt_pin_handler(args, client):
    return prompt_pin(client)

def send_pin_handler(args, client):
    return send_pin(client, pin=args.pin)

def process_commands(args):
    parser = argparse.ArgumentParser(description='Access and send commands to a hardware wallet device. Responses are in JSON format')
    parser.add_argument('--device-path', '-d', help='Specify the device path of the device to connect to')
    parser.add_argument('--device-type', '-t', help='Specify the type of device that will be connected. If `--device-path` not given, the first device of this type enumerated is used.')
    parser.add_argument('--password', '-p', help='Device password if it has one (e.g. DigitalBitbox)', default='')
    parser.add_argument('--stdinpass', help='Enter the device password on the command line', action='store_true')
    parser.add_argument('--testnet', help='Use testnet prefixes', action='store_true')
    parser.add_argument('--debug', help='Print debug statements', action='store_true')
    parser.add_argument('--fingerprint', '-f', help='Specify the device to connect to using the first 4 bytes of the hash160 of the master public key. It will connect to the first device that matches this fingerprint.')

    subparsers = parser.add_subparsers(description='Commands', dest='command')
    # work-around to make subparser required
    subparsers.required = True

    enumerate_parser = subparsers.add_parser('enumerate', help='List all available devices')
    enumerate_parser.set_defaults(func=enumerate_handler)

    getmasterxpub_parser = subparsers.add_parser('getmasterxpub', help='Get the extended public key at m/44\'/0\'/0\'')
    getmasterxpub_parser.set_defaults(func=getmasterxpub_handler)

    signtx_parser = subparsers.add_parser('signtx', help='Sign a PSBT')
    signtx_parser.add_argument('psbt', help='The Partially Signed Bitcoin Transaction to sign')
    signtx_parser.set_defaults(func=signtx_handler)

    getxpub_parser = subparsers.add_parser('getxpub', help='Get an extended public key')
    getxpub_parser.add_argument('path', help='The BIP 32 derivation path to derive the key at')
    getxpub_parser.set_defaults(func=getxpub_handler)

    signmsg_parser = subparsers.add_parser('signmessage', help='Sign a message')
    signmsg_parser.add_argument('message', help='The message to sign')
    signmsg_parser.add_argument('path', help='The BIP 32 derivation path of the key to sign the message with')
    signmsg_parser.set_defaults(func=signmessage_handler)

    getkeypool_parser = subparsers.add_parser('getkeypool', help='Get JSON array of keys that can be imported to Bitcoin Core with importmulti')
    getkeypool_parser.add_argument('--keypool', action='store_true', help='Indicates that the keys are to be imported to the keypool')
    getkeypool_parser.add_argument('--internal', action='store_true', help='Indicates that the keys are change keys')
    getkeypool_parser.add_argument('--sh_wpkh', action='store_true', help='Generate p2sh-nested segwit addresses (default path: m/49h/0h/0h/[0,1]/*)')
    getkeypool_parser.add_argument('--wpkh', action='store_true', help='Generate bech32 addresses (default path: m/84h/0h/0h/[0,1]/*)')
    getkeypool_parser.add_argument('--account', help='BIP43 account (default: 0)', type=int, default=0)
    getkeypool_parser.add_argument('--path', help='Derivation path, default follows BIP43 convention, e.g. m/84h/0h/0h/1/* with --wpkh --internal')
    getkeypool_parser.add_argument('start', type=int, help='The index to start at.')
    getkeypool_parser.add_argument('end', type=int, help='The index to end at.')
    getkeypool_parser.set_defaults(func=getkeypool_handler)

    displayaddr_parser = subparsers.add_parser('displayaddress', help='Display an address')
    displayaddr_parser.add_argument('path', help='The BIP 32 derivation path of the key embedded in the address')
    displayaddr_parser.add_argument('--sh_wpkh', action='store_true', help='Display the p2sh-nested segwit address associated with this key path')
    displayaddr_parser.add_argument('--wpkh', action='store_true', help='Display the bech32 version of the address associated with this key path')
    displayaddr_parser.set_defaults(func=displayaddress_handler)

    setupdev_parser = subparsers.add_parser('setup', help='Setup a device. Passphrase protection uses the password given by -p')
    setupdev_parser.add_argument('--label', '-l', help='The name to give to the device', default='')
    setupdev_parser.add_argument('--backup_passphrase', '-b', help='The passphrase to use for the backup, if applicable', default='')
    setupdev_parser.set_defaults(func=setup_device_handler)

    wipedev_parser = subparsers.add_parser('wipe', help='Wipe a device')
    wipedev_parser.set_defaults(func=wipe_device_handler)

    restore_parser = subparsers.add_parser('restore', help='Initiate the device restoring process')
    restore_parser.add_argument('--label', '-l', help='The name to give to the device', default='')
    restore_parser.set_defaults(func=restore_device_handler)

    backup_parser = subparsers.add_parser('backup', help='Initiate the device backup creation process')
    backup_parser.add_argument('--label', '-l', help='The name to give to the device', default='')
    backup_parser.add_argument('--backup_passphrase', '-b', help='The passphrase to use for the backup, if applicable', default='')
    backup_parser.set_defaults(func=backup_device_handler)

    promptpin_parser = subparsers.add_parser('promptpin', help='Have the device prompt for your PIN')
    promptpin_parser.set_defaults(func=prompt_pin_handler)

    sendpin_parser = subparsers.add_parser('sendpin', help='Send the numeric positions for your PIN to the device')
    sendpin_parser.add_argument('pin', help='The numeric positions of the PIN')
    sendpin_parser.set_defaults(func=send_pin_handler)

    args = parser.parse_args(args)

    device_path = args.device_path
    device_type = args.device_type
    password = args.password
    command = args.command

    # Setup debug logging
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING)

    # Enter the password on stdin
    if args.stdinpass:
        password = getpass.getpass('Enter your device password: ')
        args.password = password

    # List all available hardware wallet devices
    if command == 'enumerate':
        return args.func(args)

    # Auto detect if we are using fingerprint or type to identify device
    if args.fingerprint or (args.device_type and not args.device_path):
        client = find_device(args.device_path, args.password, args.device_type, args.fingerprint)
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

def main():
    result = process_commands(sys.argv[1:])
    print(json.dumps(result))
