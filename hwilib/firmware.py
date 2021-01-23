# Firmware download things

import datetime
import feedparser
import json
import logging
import os
import re
import requests
import sys

from urllib.parse import urlparse

from . import __version__
from .cli import HWIArgumentParser
from .errors import BadArgumentError, handle_errors, UnknownDeviceError

def format_success(model, fw_version, filepath):
    return {'success': True, 'message': '{} firmware version {} downloaded to {}'.format(model, fw_version, filepath), 'filepath': filepath}

def _download_file(url):
    filename = os.path.basename(urlparse(url).path)

    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

    return os.path.abspath(filename)

def _trezor_download(version=None, bitcoinonly=False, device_version=1):
    releases = requests.get('https://wallet.trezor.io/data/firmware/{}/releases.json'.format(device_version)).json()
    if not releases:
        raise IOError('Could not get list of releases')

    if bitcoinonly:
        releases = [r for r in releases if "url_bitcoinonly" in r]
    releases.sort(key=lambda r: r["version"], reverse=True)

    version_info = {}
    if version is None:
        version_info = releases[0]
        version = '.'.join([str(x) for x in version_info['version']])
    else:
        version_list = [int(x) for x in version.split(".")]
        for r in releases:
            if r['version'] == version_list:
                version_info = r
                break
        else:
            raise BadArgumentError('{} is not available'.format(version))

    url = 'https://wallet.trezor.io/{}'.format(version_info['url_bitcoinonly'] if bitcoinonly else version_info['url'])
    downloaded_file = _download_file(url)

    model = 'Trezor '
    if device_version == 1:
        model += '1'
    elif device_version == 2:
        model += 'T'
    else:
        raise BadArgumentError('Unknown device_version {}'.format(device_version))
    if bitcoinonly:
        model += ' Bitcoin only'

    return format_success(model, version, downloaded_file)

def trezor_1_download(version=None, bitcoinonly=False):
    return _trezor_download(version, bitcoinonly, 1)

def trezor_t_download(version=None, bitcoinonly=False):
    return _trezor_download(version, bitcoinonly, 2)

def coldcard_download(version=None, bitcoinonly=False):
    versions = feedparser.parse('https://github.com/Coldcard/firmware/tags.atom')
    releases = versions.entries

    def coldcard_version_formatted(ver_str):
        try:
            return bool(datetime.datetime.strptime(ver_str[:15], '%Y-%m-%dT%H%M'))
        except:
            return False

    releases = [r for r in releases if coldcard_version_formatted(r['title'])]
    releases.sort(key=lambda r: r["updated_parsed"], reverse=True)

    version_info = {}
    if version is None:
        version_info = releases[0]
        version = version_info['title'][17:]
    else:
        for r in releases:
            if r['title'][15:] == '-v{}'.format(version):
                version_info = r
                break
        else:
            raise BadArgumentError('{} is not available'.format(version))

    filename = '{}-coldcard.dfu'.format(version_info['title'])
    url = 'https://github.com/Coldcard/firmware/blob/master/releases/{}?raw=true'.format(filename)
    downloaded_file = _download_file(url)

    return format_success('Coldcard', version, downloaded_file)

def keepkey_download(version=None, bitcoinonly=False):
    versions = feedparser.parse('https://github.com/keepkey/keepkey-firmware/tags.atom')
    releases = versions.entries

    def keepkey_id_formatted(id_str):
        tag = id_str.split('/')[-1]
        p = re.compile(r'^v\d+.\d+.\d$')
        return bool(p.match(tag))

    releases = [r for r in releases if keepkey_id_formatted(r['id'])]
    releases.sort(key=lambda r: r["updated_parsed"], reverse=True)

    version_info = {}
    if version is None:
        version_info = releases[0]
        version = version_info['id'].split('/')[-1][1:]
    else:
        for r in releases:
            if r['id'].split('/')[-1][1:] == version:
                version_info = r
                break
        else:
            raise BadArgumentError('{} is not available'.format(version))

    url = 'https://github.com/keepkey/keepkey-firmware/releases/download/v{}/firmware.keepkey.bin'.format(version)
    downloaded_file = _download_file(url)

    return format_success('Keepkey', version, downloaded_file)

def digitalbitbox_01_download(version=None, bitcoinonly=False):
    versions = feedparser.parse('https://github.com/digitalbitbox/mcu/tags.atom')
    releases = versions.entries

    def id_formatted(id_str):
        tag = id_str.split('/')[-1]
        p = re.compile(r'^v\d+.\d+.\d$')
        return bool(p.match(tag))

    releases = [r for r in releases if id_formatted(r['id'])]
    releases.sort(key=lambda r: r["updated_parsed"], reverse=True)

    version_info = {}
    if version is None:
        version_info = releases[0]
        version = version_info['id'].split('/')[-1][1:]
    else:
        for r in releases:
            if r['id'].split('/')[-1][1:] == version:
                version_info = r
                break
        else:
            raise BadArgumentError('{} is not available'.format(version))

    url = 'https://github.com/digitalbitbox/mcu/releases/download/v{}/firmware.deterministic.{}.signed.bin'.format(version, version)
    downloaded_file = _download_file(url)

    return format_success('Digital Bitbox01', version, downloaded_file)

def download_firmware(model, version, bitcoinonly=False):
    dev_model = model.lower()
    func_name = dev_model + '_download'

    try:
        dl_func = globals()[func_name]
        return dl_func(version, bitcoinonly)
    except KeyError:
        raise UnknownDeviceError('No Download function for {}'.format(dev_model))

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
