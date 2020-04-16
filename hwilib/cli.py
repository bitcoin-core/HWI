#! /usr/bin/env python3

from .commands import backup_device, displayaddress, enumerate, find_device, \
    get_client, getmasterxpub, getxpub, getkeypool, getdescriptors, prompt_pin, toggle_passphrase, restore_device, send_pin, setup_device, \
    signmessage, signtx, wipe_device, install_udev_rules
from .errors import (
    handle_errors,
    DEVICE_CONN_ERROR,
    HELP_TEXT,
    MISSING_ARGUMENTS,
    NO_DEVICE_TYPE,
    UNAVAILABLE_ACTION
)
from . import __version__

import argparse
import getpass
import logging
import json
import sys

def backup_device_handler(args, client):
    return backup_device(client, label=args.label, backup_passphrase=args.backup_passphrase)

def displayaddress_handler(args, client):
    return displayaddress(client, desc=args.desc, path=args.path, sh_wpkh=args.sh_wpkh, wpkh=args.wpkh)

def enumerate_handler(args):
    return enumerate(password=args.password)

def getmasterxpub_handler(args, client):
    return getmasterxpub(client)

def getxpub_handler(args, client):
    return getxpub(client, path=args.path)

def getkeypool_handler(args, client):
    return getkeypool(client, path=args.path, start=args.start, end=args.end, internal=args.internal, keypool=args.keypool, account=args.account, sh_wpkh=args.sh_wpkh, wpkh=args.wpkh, addr_all=args.all)

def getdescriptors_handler(args, client):
    return getdescriptors(client, account=args.account)

def restore_device_handler(args, client):
    if args.interactive:
        return restore_device(client, label=args.label, word_count=args.word_count)
    return {'error': 'restore requires interactive mode', 'code': UNAVAILABLE_ACTION}

def setup_device_handler(args, client):
    if args.interactive:
        return setup_device(client, label=args.label, backup_passphrase=args.backup_passphrase)
    return {'error': 'setup requires interactive mode', 'code': UNAVAILABLE_ACTION}

def signmessage_handler(args, client):
    return signmessage(client, message=args.message, path=args.path)

def signtx_handler(args, client):
    return signtx(client, psbt=args.psbt)

def wipe_device_handler(args, client):
    return wipe_device(client)

def prompt_pin_handler(args, client):
    return prompt_pin(client)

def toggle_passphrase_handler(args, client):
    return toggle_passphrase(client)

def send_pin_handler(args, client):
    return send_pin(client, pin=args.pin)

def install_udev_rules_handler(args):
    return install_udev_rules('udev', args.location)

class HWIHelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass

class HWIArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.formatter_class = HWIHelpFormatter

    def print_usage(self, file=None):
        if file is None:
            file = sys.stderr
        super().print_usage(file)

    def print_help(self, file=None):
        if file is None:
            file = sys.stderr
        super().print_help(file)
        error = {'error': 'Help text requested', 'code': HELP_TEXT}
        print(json.dumps(error))

    def error(self, message):
        self.print_usage(sys.stderr)
        args = {'prog': self.prog, 'message': message}
        error = {'error': '%(prog)s: error: %(message)s' % args, 'code': MISSING_ARGUMENTS}
        print(json.dumps(error))
        self.exit(2)

def process_commands(cli_args):
    parser = HWIArgumentParser(description='Hardware Wallet Interface, version {}.\nAccess and send commands to a hardware wallet device. Responses are in JSON format.'.format(__version__))
    parser.add_argument('--device-path', '-d', help='Specify the device path of the device to connect to')
    parser.add_argument('--device-type', '-t', help='Specify the type of device that will be connected. If `--device-path` not given, the first device of this type enumerated is used.')
    parser.add_argument('--password', '-p', help='Device password if it has one (e.g. DigitalBitbox)', default='')
    parser.add_argument('--stdinpass', help='Enter the device password on the command line', action='store_true')
    parser.add_argument('--testnet', help='Use testnet prefixes', action='store_true')
    parser.add_argument('--debug', help='Print debug statements', action='store_true')
    parser.add_argument('--fingerprint', '-f', help='Specify the device to connect to using the first 4 bytes of the hash160 of the master public key. It will connect to the first device that matches this fingerprint.')
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(__version__))
    parser.add_argument('--stdin', help='Enter commands and arguments via stdin', action='store_true')
    parser.add_argument('--interactive', '-i', help='Use some commands interactively. Currently required for all device configuration commands', action='store_true')
    parser.add_argument('--expert', help='Do advanced things and get more detailed information returned from some commands. Use at your own risk.', action='store_true')

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
    kparg_group = getkeypool_parser.add_mutually_exclusive_group()
    kparg_group.add_argument('--keypool', action='store_true', dest='keypool', help='Indicates that the keys are to be imported to the keypool', default=True)
    kparg_group.add_argument('--nokeypool', action='store_false', dest='keypool', help='Indicates that the keys are not to be imported to the keypool', default=False)
    getkeypool_parser.add_argument('--internal', action='store_true', help='Indicates that the keys are change keys')
    kp_type_group = getkeypool_parser.add_mutually_exclusive_group()
    kp_type_group.add_argument('--sh_wpkh', action='store_true', help='Generate p2sh-nested segwit addresses (default path: m/49h/0h/0h/[0,1]/*)')
    kp_type_group.add_argument('--wpkh', action='store_true', help='Generate bech32 addresses (default path: m/84h/0h/0h/[0,1]/*)')
    kp_type_group.add_argument('--all', action='store_true', help='Generate addresses for all standard address types (default paths: m/{44,49,84}h/0h/0h/[0,1]/*)')
    getkeypool_parser.add_argument('--account', help='BIP43 account', type=int, default=0)
    getkeypool_parser.add_argument('--path', help='Derivation path, default follows BIP43 convention, e.g. m/84h/0h/0h/1/* with --wpkh --internal. If this argument and --internal is not given, both internal and external keypools will be returned.')
    getkeypool_parser.add_argument('start', type=int, help='The index to start at.')
    getkeypool_parser.add_argument('end', type=int, help='The index to end at.')
    getkeypool_parser.set_defaults(func=getkeypool_handler)

    getdescriptors_parser = subparsers.add_parser('getdescriptors', help='Return receive and change descriptors for each supported address type, for import into a wallet.')
    getdescriptors_parser.add_argument('--account', help='BIP43 account', type=int, default=0)
    getdescriptors_parser.set_defaults(func=getdescriptors_handler)

    displayaddr_parser = subparsers.add_parser('displayaddress', help='Display an address')
    group = displayaddr_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--desc', help='Output Descriptor. E.g. wpkh([00000000/84h/0h/0h]xpub.../0/0), where 00000000 must match --fingerprint and xpub can be obtained with getxpub. See doc/descriptors.md in Bitcoin Core')
    group.add_argument('--path', help='The BIP 32 derivation path of the key embedded in the address, default follows BIP43 convention, e.g. m/84h/0h/0h/1/*')
    displayaddr_parser.add_argument('--sh_wpkh', action='store_true', help='Display the p2sh-nested segwit address associated with this key path')
    displayaddr_parser.add_argument('--wpkh', action='store_true', help='Display the bech32 version of the address associated with this key path')
    displayaddr_parser.set_defaults(func=displayaddress_handler)

    setupdev_parser = subparsers.add_parser('setup', help='Setup a device. Passphrase protection uses the password given by -p. Requires interactive mode')
    setupdev_parser.add_argument('--label', '-l', help='The name to give to the device', default='')
    setupdev_parser.add_argument('--backup_passphrase', '-b', help='The passphrase to use for the backup, if applicable', default='')
    setupdev_parser.set_defaults(func=setup_device_handler)

    wipedev_parser = subparsers.add_parser('wipe', help='Wipe a device')
    wipedev_parser.set_defaults(func=wipe_device_handler)

    restore_parser = subparsers.add_parser('restore', help='Initiate the device restoring process. Requires interactive mode')
    restore_parser.add_argument('--word_count', '-w', help='Word count of your BIP39 recovery phrase (options: 12/18/24)', type=int, default=24)
    restore_parser.add_argument('--label', '-l', help='The name to give to the device', default='')
    restore_parser.set_defaults(func=restore_device_handler)

    backup_parser = subparsers.add_parser('backup', help='Initiate the device backup creation process')
    backup_parser.add_argument('--label', '-l', help='The name to give to the device', default='')
    backup_parser.add_argument('--backup_passphrase', '-b', help='The passphrase to use for the backup, if applicable', default='')
    backup_parser.set_defaults(func=backup_device_handler)

    promptpin_parser = subparsers.add_parser('promptpin', help='Have the device prompt for your PIN')
    promptpin_parser.set_defaults(func=prompt_pin_handler)

    togglepassphrase_parser = subparsers.add_parser('togglepassphrase', help='Toggle BIP39 passphrase protection')
    togglepassphrase_parser.set_defaults(func=toggle_passphrase_handler)

    sendpin_parser = subparsers.add_parser('sendpin', help='Send the numeric positions for your PIN to the device')
    sendpin_parser.add_argument('pin', help='The numeric positions of the PIN')
    sendpin_parser.set_defaults(func=send_pin_handler)

    if sys.platform.startswith("linux"):
        udevrules_parser = subparsers.add_parser('installudevrules', help='Install and load the udev rule files for the hardware wallet devices')
        udevrules_parser.add_argument('--location', help='The path where the udev rules files will be copied', default='/etc/udev/rules.d/')
        udevrules_parser.set_defaults(func=install_udev_rules_handler)

    if any(arg == '--stdin' for arg in cli_args):
        while True:
            try:
                line = input()
                # Exit loop when we see 2 consecutive newlines (i.e. an empty line)
                if line == '':
                    break
                # Split the line and append it to the cli args
                import shlex
                cli_args.extend(shlex.split(line))
            except EOFError:
                # If we see EOF, stop taking input
                break

    # Parse arguments again for anything entered over stdin
    args = parser.parse_args(cli_args)

    device_path = args.device_path
    device_type = args.device_type
    password = args.password
    command = args.command
    result = {}

    # Setup debug logging
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING)

    # Enter the password on stdin
    if args.stdinpass:
        password = getpass.getpass('Enter your device password: ')
        args.password = password

    # List all available hardware wallet devices
    if command == 'enumerate':
        return args.func(args)

    # Install the devices udev rules for Linux
    if command == 'installudevrules':
        with handle_errors(msg="installudevrules failed:", result=result):
            result = args.func(args)
        return result

    # Auto detect if we are using fingerprint or type to identify device
    if args.fingerprint or (args.device_type and not args.device_path):
        client = find_device(args.password, args.device_type, args.fingerprint, args.expert)
        if not client:
            return {'error': 'Could not find device with specified fingerprint', 'code': DEVICE_CONN_ERROR}
    elif args.device_type and args.device_path:
        with handle_errors(result=result, code=DEVICE_CONN_ERROR):
            client = get_client(device_type, device_path, password, args.expert)
        if 'error' in result:
            return result
    else:
        return {'error': 'You must specify a device type or fingerprint for all commands except enumerate', 'code': NO_DEVICE_TYPE}

    client.is_testnet = args.testnet

    # Do the commands
    with handle_errors(result=result, debug=args.debug):
        result = args.func(args, client)

    with handle_errors(result=result, debug=args.debug):
        client.close()

    return result

def main():
    result = process_commands(sys.argv[1:])
    print(json.dumps(result))
