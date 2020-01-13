#! /usr/bin/env bash

import json
import logging
import sys

from . import __version__
from .cli import HWIArgumentParser
from .errors import handle_errors

def download_firmware(model, version, bitcoinonly):
    return {}

def process_commands(cli_args):
    parser = HWIArgumentParser(description='Hardware Wallet Interface Firmware Updater and Downloader, version {}.\nDownload and update firmware for harware wallets. Responses are in JSON format.'.format(__version__))
    parser.add_argument('model', help='The name of the device model you want to download firmware for')
    parser.add_argument('--firmware-version', '-f', help='The version number to download. If ommitted, download the latest.')
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(__version__))
    parser.add_argument('--debug', help='Print debug statements', action='store_true')
    parser.add_argument('--bitcoinonly', help='Download the Bitcoin only firmware if it is available', action='store_true')
    args = parser.parse_args(cli_args)

    # Setup debug logging
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING)

    # Do the commands
    result = {}
    with handle_errors(result=result, debug=args.debug):
        result = download_firmware(args.model, args.firmware_version, args.bitcoinonly)

    return result

def main():
    result = process_commands(sys.argv[1:])
    print(json.dumps(result))
