#! /usr/bin/env python3

# Hardware wallet interaction script

import importlib
import platform

from .serializations import PSBT
from .base58 import xpub_to_pub_hex
from .errors import UnknownDeviceError, BAD_ARGUMENT, NOT_IMPLEMENTED
from .descriptor import Descriptor
from .devices import __all__ as all_devs
from enum import Enum

class AddressType(Enum):
    PKH = 1
    WPKH = 2
    SH_WPKH = 3

# Get the client for the device
def get_client(device_type, device_path, password='', expert=False):
    device_type = device_type.split('_')[0]
    class_name = device_type.capitalize()
    module = device_type.lower()

    client = None
    try:
        imported_dev = importlib.import_module('.devices.' + module, __package__)
        client_constructor = getattr(imported_dev, class_name + 'Client')
        client = client_constructor(device_path, password, expert)
    except ImportError:
        if client:
            client.close()
        raise UnknownDeviceError('Unknown device type specified')

    return client

# Get a list of all available hardware wallets
def enumerate(password=''):
    result = []

    for module in all_devs:
        try:
            imported_dev = importlib.import_module('.devices.' + module, __package__)
            result.extend(imported_dev.enumerate(password))
        except ImportError:
            pass # Ignore ImportErrors, the user may not have all device dependencies installed
    return result

# Fingerprint or device type required
def find_device(password='', device_type=None, fingerprint=None, expert=False):
    devices = enumerate(password)
    for d in devices:
        if device_type is not None and d['type'] != device_type and d['model'] != device_type:
            continue
        client = None
        try:
            client = get_client(d['type'], d['path'], password, expert)

            master_fpr = d.get('fingerprint', None)
            if master_fpr is None:
                master_fpr = client.get_master_fingerprint_hex()

            if fingerprint and master_fpr != fingerprint:
                client.close()
                continue
            return client
        except:
            if client:
                client.close()
            pass # Ignore things we wouldn't get fingerprints for
    return None

def getmasterxpub(client):
    return client.get_master_xpub()

def signtx(client, psbt):
    # Deserialize the transaction
    tx = PSBT()
    tx.deserialize(psbt)
    return client.sign_tx(tx)

def getxpub(client, path):
    return client.get_pubkey_at_path(path)

def signmessage(client, message, path):
    return client.sign_message(message, path)

def getkeypool_inner(client, path, start, end, internal=False, keypool=True, account=0, addr_type=AddressType.WPKH):

    try:
        master_fpr = client.get_master_fingerprint_hex()
    except NotImplementedError as e:
        return {'error': str(e), 'code': NOT_IMPLEMENTED}

    desc = getdescriptor(client, master_fpr, client.is_testnet, path, internal, addr_type, account, start, end)

    if not isinstance(desc, Descriptor):
        return desc

    this_import = {}

    this_import['desc'] = desc.serialize()
    this_import['range'] = [start, end]
    this_import['timestamp'] = 'now'
    this_import['internal'] = internal
    this_import['keypool'] = keypool
    this_import['active'] = keypool
    this_import['watchonly'] = True
    return [this_import]

def getdescriptor(client, master_fpr, testnet=False, path=None, internal=False, addr_type=AddressType.WPKH, account=0, start=None, end=None):
    testnet = client.is_testnet

    is_wpkh = addr_type is AddressType.WPKH
    is_sh_wpkh = addr_type is AddressType.SH_WPKH

    if not path:
        # Master key:
        path = "m/"

        # Purpose
        if is_wpkh:
            path += "84'/"
        elif is_sh_wpkh:
            path += "49'/"
        else:
            assert addr_type == AddressType.PKH
            path += "44'/"

        # Coin type
        if testnet:
            path += "1'/"
        else:
            path += "0'/"

        # Account
        path += str(account) + '\'/'

        # Receive or change
        if internal:
            path += "1/*"
        else:
            path += "0/*"
    else:
        if path[0] != "m":
            return {'error': 'Path must start with m/', 'code': BAD_ARGUMENT}
        if path[-1] != "*":
            return {'error': 'Path must end with /*', 'code': BAD_ARGUMENT}

    # Find the last hardened derivation:
    path = path.replace('\'', 'h')
    path_suffix = ''
    for component in path.split("/")[::-1]:
        if component[-1] == 'h' or component[-1] == 'm':
            break
        path_suffix = '/' + component + path_suffix
    path_base = path.rsplit(path_suffix)[0]

    # Get the key at the base
    if client.xpub_cache.get(path_base) is None:
        client.xpub_cache[path_base] = client.get_pubkey_at_path(path_base)['xpub']

    return Descriptor(master_fpr, path_base.replace('m', ''), client.xpub_cache.get(path_base), path_suffix, client.is_testnet, is_sh_wpkh, is_wpkh)

def getkeypool(client, path, start, end, internal=False, keypool=True, account=0, sh_wpkh=False, wpkh=True, addr_all=False):

    if sh_wpkh:
        addr_types = [AddressType.SH_WPKH]
    elif wpkh:
        addr_types = [AddressType.WPKH]
    elif addr_all:
        addr_types = list(AddressType)
    else:
        addr_types = [AddressType.PKH]

    # When no specific path or internal-ness is specified, create standard types
    chains = []
    if path is None and not internal:
        for addr_type in addr_types:
            for internal_addr in [False, True]:
                chains = chains + getkeypool_inner(client, None, start, end, internal_addr, keypool, account, addr_type)

        # Report the first error we encounter
        for chain in chains:
            if 'error' in chain:
                return chain
        # No errors, return pair
        return chains
    else:
        assert len(addr_types) == 1
        return getkeypool_inner(client, path, start, end, internal, keypool, account, addr_types[0])


def getdescriptors(client, account=0):
    try:
        master_fpr = client.get_master_fingerprint_hex()
    except NotImplementedError as e:
        return {'error': str(e), 'code': NOT_IMPLEMENTED}

    result = {}

    for internal in [False, True]:
        descriptors = []
        desc1 = getdescriptor(client, master_fpr=master_fpr, testnet=client.is_testnet, internal=internal, addr_type=AddressType.PKH, account=account)
        desc2 = getdescriptor(client, master_fpr=master_fpr, testnet=client.is_testnet, internal=internal, addr_type=AddressType.SH_WPKH, account=account)
        desc3 = getdescriptor(client, master_fpr=master_fpr, testnet=client.is_testnet, internal=internal, addr_type=AddressType.WPKH, account=account)
        for desc in [desc1, desc2, desc3]:
            if not isinstance(desc, Descriptor):
                return desc
            descriptors.append(desc.serialize())
        if internal:
            result["internal"] = descriptors
        else:
            result["receive"] = descriptors

    return result

def displayaddress(client, path=None, desc=None, sh_wpkh=False, wpkh=False):
    if path is not None:
        if sh_wpkh and wpkh:
            return {'error': 'Both `--wpkh` and `--sh_wpkh` can not be selected at the same time.', 'code': BAD_ARGUMENT}
        return client.display_address(path, sh_wpkh, wpkh)
    elif desc is not None:
        if sh_wpkh or wpkh:
            return {'error': ' `--wpkh` and `--sh_wpkh` can not be combined with --desc', 'code': BAD_ARGUMENT}
        descriptor = Descriptor.parse(desc, client.is_testnet)
        if descriptor is None:
            return {'error': 'Unable to parse descriptor: ' + desc, 'code': BAD_ARGUMENT}
        if descriptor.m_path is None:
            return {'error': 'Descriptor missing origin info: ' + desc, 'code': BAD_ARGUMENT}
        if descriptor.origin_fingerprint != client.get_master_fingerprint_hex():
            return {'error': 'Descriptor fingerprint does not match device: ' + desc, 'code': BAD_ARGUMENT}
        xpub = client.get_pubkey_at_path(descriptor.m_path_base)['xpub']
        if descriptor.base_key != xpub and descriptor.base_key != xpub_to_pub_hex(xpub):
            return {'error': 'Key in descriptor does not match device: ' + desc, 'code': BAD_ARGUMENT}
        return client.display_address(descriptor.m_path, descriptor.sh_wpkh, descriptor.wpkh)

def setup_device(client, label='', backup_passphrase=''):
    return client.setup_device(label, backup_passphrase)

def wipe_device(client):
    return client.wipe_device()

def restore_device(client, label='', word_count=24):
    return client.restore_device(label, word_count)

def backup_device(client, label='', backup_passphrase=''):
    return client.backup_device(label, backup_passphrase)

def prompt_pin(client):
    return client.prompt_pin()

def send_pin(client, pin):
    return client.send_pin(pin)

def toggle_passphrase(client):
    return client.toggle_passphrase()

def install_udev_rules(source, location):
    if platform.system() == "Linux":
        from .udevinstaller import UDevInstaller
        return UDevInstaller.install(source, location)
    return {'error': 'udev rules are not needed on your platform', 'code': NOT_IMPLEMENTED}
