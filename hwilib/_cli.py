#! /usr/bin/env python3

from .commands import (
    backup_device,
    displayaddress,
    enumerate,
    find_device,
    get_client,
    getmasterxpub,
    getxpub,
    getkeypool,
    getdescriptors,
    prompt_pin,
    toggle_passphrase,
    restore_device,
    send_pin,
    setup_device,
    signmessage,
    signtx,
    wipe_device,
    install_udev_rules,
)
from .common import (
    AddressType,
    Chain,
)
from .errors import (
    handle_errors,
    DEVICE_CONN_ERROR,
    HELP_TEXT,
    MISSING_ARGUMENTS,
    NO_DEVICE_TYPE,
    UnavailableActionError,
    UNKNOWN_ERROR,
)
from .hwwclient import HardwareWalletClient
from . import __version__

import argparse
import getpass
import logging
import json
import sys

from typing import (
    Any,
    Dict,
    IO,
    List,
    NoReturn,
    Optional,
    Union,
)


def backup_device_handler(args: argparse.Namespace, client: HardwareWalletClient) -> Dict[str, bool]:
    return backup_device(client, label=args.label, backup_passphrase=args.backup_passphrase)

def displayaddress_handler(args: argparse.Namespace, client: HardwareWalletClient) -> Dict[str, str]:
    return displayaddress(client, desc=args.desc, path=args.path, addr_type=args.addr_type)

def enumerate_handler(args: argparse.Namespace) -> List[Dict[str, Any]]:
    return enumerate(password=args.password, expert=args.expert, chain=args.chain, allow_emulators=args.allow_emulators)

def getmasterxpub_handler(args: argparse.Namespace, client: HardwareWalletClient) -> Dict[str, str]:
    return getmasterxpub(client, addrtype=args.addr_type, account=args.account)

def getxpub_handler(args: argparse.Namespace, client: HardwareWalletClient) -> Dict[str, str]:
    return getxpub(client, path=args.path, expert=args.expert)

def getkeypool_handler(args: argparse.Namespace, client: HardwareWalletClient) -> List[Dict[str, Any]]:
    return getkeypool(client, path=args.path, start=args.start, end=args.end, internal=args.internal, keypool=args.keypool, account=args.account, addr_type=args.addr_type, addr_all=args.all)

def getdescriptors_handler(args: argparse.Namespace, client: HardwareWalletClient) -> Dict[str, List[str]]:
    return getdescriptors(client, account=args.account)

def restore_device_handler(args: argparse.Namespace, client: HardwareWalletClient) -> Dict[str, bool]:
    if args.interactive:
        return restore_device(client, label=args.label, word_count=args.word_count)
    raise UnavailableActionError("restore requires interactive mode")

def setup_device_handler(args: argparse.Namespace, client: HardwareWalletClient) -> Dict[str, bool]:
    if args.interactive:
        return setup_device(client, label=args.label, backup_passphrase=args.backup_passphrase)
    raise UnavailableActionError("setup requires interactive mode")

def signmessage_handler(args: argparse.Namespace, client: HardwareWalletClient) -> Dict[str, str]:
    return signmessage(client, message=args.message, path=args.path)

def signtx_handler(args: argparse.Namespace, client: HardwareWalletClient) -> Dict[str, Union[bool, str]]:
    return signtx(client, psbt=args.psbt)

def wipe_device_handler(args: argparse.Namespace, client: HardwareWalletClient) -> Dict[str, bool]:
    return wipe_device(client)

def prompt_pin_handler(args: argparse.Namespace, client: HardwareWalletClient) -> Dict[str, bool]:
    return prompt_pin(client)

def toggle_passphrase_handler(args: argparse.Namespace, client: HardwareWalletClient) -> Dict[str, bool]:
    return toggle_passphrase(client)

def send_pin_handler(args: argparse.Namespace, client: HardwareWalletClient) -> Dict[str, bool]:
    return send_pin(client, pin=args.pin)

def install_udev_rules_handler(args: argparse.Namespace) -> Dict[str, bool]:
    return install_udev_rules('udev', args.location)

class HWIHelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass

class HWIArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.formatter_class = HWIHelpFormatter

    def print_usage(self, file: Optional[IO[str]] = None) -> None:
        if file is None:
            file = sys.stderr
        super().print_usage(file)

    def print_help(self, file: Optional[IO[str]] = None) -> None:
        if file is None:
            file = sys.stderr
        super().print_help(file)
        error = {'error': 'Help text requested', 'code': HELP_TEXT}
        print(json.dumps(error))

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        args = {'prog': self.prog, 'message': message}
        error = {'error': '%(prog)s: error: %(message)s' % args, 'code': MISSING_ARGUMENTS}
        print(json.dumps(error))
        self.exit(2)

def get_parser() -> HWIArgumentParser:
    parser = HWIArgumentParser(description='Hardware Wallet Interface, version {}.\nAccess and send commands to a hardware wallet device. Responses are in JSON format.'.format(__version__))
    parser.add_argument('--device-path', '-d', help='Specify the device path of the device to connect to')
    parser.add_argument('--device-type', '-t', help='Specify the type of device that will be connected. If `--device-path` not given, the first device of this type enumerated is used.')
    parser.add_argument('--password', '-p', help='Device password if it has one (e.g. DigitalBitbox)')
    parser.add_argument('--stdinpass', help='Enter the device password on the command line', action='store_true')
    parser.add_argument('--chain', help='Select chain to work with', type=Chain.argparse, choices=list(Chain), default=Chain.MAIN) # type: ignore
    parser.add_argument('--debug', help='Print debug statements', action='store_true')
    parser.add_argument('--fingerprint', '-f', help='Specify the device to connect to using the first 4 bytes of the hash160 of the master public key. It will connect to the first device that matches this fingerprint.')
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(__version__))
    parser.add_argument('--stdin', help='Enter commands and arguments via stdin', action='store_true')
    parser.add_argument('--interactive', '-i', help='Use some commands interactively. Currently required for all device configuration commands', action='store_true')
    parser.add_argument('--expert', help='Do advanced things and get more detailed information returned from some commands. Use at your own risk.', action='store_true')
    parser.add_argument("--emulators", help="Enable enumeration and detection of device emulators", action="store_true", dest="allow_emulators")

    subparsers = parser.add_subparsers(description='Commands', dest='command')
    # work-around to make subparser required
    subparsers.required = True

    enumerate_parser = subparsers.add_parser('enumerate', help='List all available devices')
    enumerate_parser.set_defaults(func=enumerate_handler)

    getmasterxpub_parser = subparsers.add_parser('getmasterxpub', help='Get the extended public key for BIP 44 standard derivation paths. Convenience function to get xpubs given the address type, account, and chain type.')
    getmasterxpub_parser.add_argument("--addr-type", help="Get the master xpub used to derive addresses for this address type", type=AddressType.argparse, choices=list(AddressType), default=AddressType.WIT) # type: ignore
    getmasterxpub_parser.add_argument("--account", help="The account number", type=int, default=0)
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
    kp_type_group.add_argument("--addr-type", help="The address type (and default derivation path) to produce descriptors for", type=AddressType.argparse, choices=list(AddressType), default=AddressType.WIT) # type: ignore
    kp_type_group.add_argument('--all', action='store_true', help='Generate addresses for all standard address types (default paths: ``m/{44,49,84}h/0h/0h/[0,1]/*)``')
    getkeypool_parser.add_argument('--account', help='BIP43 account', type=int, default=0)
    getkeypool_parser.add_argument('--path', help='Derivation path, default follows BIP43 convention, e.g. ``m/84h/0h/0h/1/*`` with --addr-type wpkh --internal. If this argument and --internal is not given, both internal and external keypools will be returned.')
    getkeypool_parser.add_argument('start', type=int, help='The index to start at.')
    getkeypool_parser.add_argument('end', type=int, help='The index to end at.')
    getkeypool_parser.set_defaults(func=getkeypool_handler)

    getdescriptors_parser = subparsers.add_parser('getdescriptors', help='Return receive and change descriptors for each supported address type, for import into a wallet.')
    getdescriptors_parser.add_argument('--account', help='BIP43 account', type=int, default=0)
    getdescriptors_parser.set_defaults(func=getdescriptors_handler)

    displayaddr_parser = subparsers.add_parser('displayaddress', help='Display an address')
    group = displayaddr_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--desc', help='Output Descriptor. E.g. wpkh([00000000/84h/0h/0h]xpub.../0/0), where 00000000 must match --fingerprint and xpub can be obtained with getxpub. See doc/descriptors.md in Bitcoin Core')
    group.add_argument('--path', help='The BIP 32 derivation path of the key embedded in the address, default follows BIP43 convention, e.g. ``m/84h/0h/0h/1/*``')
    displayaddr_parser.add_argument("--addr-type", help="The address type to display", type=AddressType.argparse, choices=list(AddressType), default=AddressType.WIT) # type: ignore
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

    return parser

def process_commands(cli_args: List[str]) -> Any:
    parser = get_parser()

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
    result: Dict[str, Any] = {}

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
        client = find_device(args.password, args.device_type, args.fingerprint, args.expert, args.chain, args.allow_emulators)
        if not client:
            return {'error': 'Could not find device with specified fingerprint or type', 'code': DEVICE_CONN_ERROR}
    elif args.device_type and args.device_path:
        with handle_errors(result=result, code=DEVICE_CONN_ERROR):
            client = get_client(device_type, device_path, password, args.expert, args.chain)
        if 'error' in result:
            return result
    else:
        return {'error': 'You must specify a device type or fingerprint for all commands except enumerate', 'code': NO_DEVICE_TYPE}

    if client is None:
        return {"error": "Unable to communicated with device", "code": UNKNOWN_ERROR}

    # Do the commands
    with handle_errors(result=result, debug=args.debug):
        result = args.func(args, client)

    with handle_errors(result=result, debug=args.debug):
        client.close()

    return result

def main() -> None:
    result = process_commands(sys.argv[1:])
    print(json.dumps(result))
