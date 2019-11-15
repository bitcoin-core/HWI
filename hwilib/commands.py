#! /usr/bin/env python3

# Hardware wallet interaction script

import importlib
import platform

from .serializations import PSBT
from .base58 import get_xpub_fingerprint_as_id, get_xpub_fingerprint_hex, xpub_to_pub_hex
from .errors import UnknownDeviceError, BAD_ARGUMENT, NOT_IMPLEMENTED
from .descriptor import Descriptor
from .devices import __all__ as all_devs

# Get the client for the device
def get_client(device_type, device_path, password=''):
    device_type = device_type.split('_')[0]
    class_name = device_type.capitalize()
    module = device_type.lower()

    client = None
    try:
        imported_dev = importlib.import_module('.devices.' + module, __package__)
        client_constructor = getattr(imported_dev, class_name + 'Client')
        client = client_constructor(device_path, password)
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
def find_device(device_path, password='', device_type=None, fingerprint=None):
    devices = enumerate(password)
    for d in devices:
        if device_type is not None and d['type'] != device_type and d['model'] != device_type:
            continue
        client = None
        try:
            client = get_client(d['type'], d['path'], password)

            master_fpr = d.get('fingerprint', None)
            if master_fpr is None:
                master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
                master_fpr = get_xpub_fingerprint_hex(master_xpub)

            if fingerprint and master_fpr != fingerprint:
                client.close()
                continue
            else:
                client.fingerprint = master_fpr
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

def getkeypool_inner(client, path, start, end, internal=False, keypool=True, account=0, sh_wpkh=False, wpkh=True):
    if sh_wpkh and wpkh:
        return {'error': 'Both `--wpkh` and `--sh_wpkh` can not be selected at the same time.', 'code': BAD_ARGUMENT}

    try:
        master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
    except NotImplementedError as e:
        return {'error': str(e), 'code': NOT_IMPLEMENTED}

    desc = getdescriptor(client, master_xpub, client.is_testnet, path, internal, sh_wpkh, wpkh, account, start, end)

    if not isinstance(desc, Descriptor):
        return desc

    this_import = {}

    this_import['desc'] = desc.serialize()
    this_import['range'] = [start, end]
    this_import['timestamp'] = 'now'
    this_import['internal'] = internal
    this_import['keypool'] = keypool
    this_import['watchonly'] = True
    return [this_import]

def getdescriptor(client, master_xpub, testnet=False, path=None, internal=False, sh_wpkh=False, wpkh=True, account=0, start=None, end=None):
    master_fpr = get_xpub_fingerprint_as_id(master_xpub)
    testnet = client.is_testnet

    if not path:
        # Master key:
        path = "m/"

        # Purpose
        if wpkh:
            path += "84'/"
        elif sh_wpkh:
            path += "49'/"
        else:
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

    return Descriptor(master_fpr, path_base.replace('m', ''), client.xpub_cache.get(path_base), path_suffix, client.is_testnet, sh_wpkh, wpkh)

# wrapper to allow both internal and external entries when path not given
def getkeypool(client, path, start, end, internal=False, keypool=True, account=0, sh_wpkh=False, wpkh=True):
    if path is None and not internal:
        internal_chain = getkeypool_inner(client, None, start, end, True, keypool, account, sh_wpkh, wpkh)
        external_chain = getkeypool_inner(client, None, start, end, False, keypool, account, sh_wpkh, wpkh)
        # Report the first error we encounter
        for chain in [internal_chain, external_chain]:
            if 'error' in chain:
                return chain
        # No errors, return pair
        return internal_chain + external_chain
    else:
        return getkeypool_inner(client, path, start, end, internal, keypool, account, sh_wpkh, wpkh)


def getdescriptors(client, account=0):
    try:
        master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
    except NotImplementedError as e:
        return {'error': str(e), 'code': NOT_IMPLEMENTED}

    result = {}

    for internal in [False, True]:
        descriptors = []
        desc1 = getdescriptor(client, master_xpub=master_xpub, testnet=client.is_testnet, internal=internal, sh_wpkh=False, wpkh=False, account=account)
        desc2 = getdescriptor(client, master_xpub=master_xpub, testnet=client.is_testnet, internal=internal, sh_wpkh=True, wpkh=False, account=account)
        desc3 = getdescriptor(client, master_xpub=master_xpub, testnet=client.is_testnet, internal=internal, sh_wpkh=False, wpkh=True, account=account)
        for desc in [desc1, desc2, desc3]:
            if not isinstance(desc, Descriptor):
                return desc
            descriptors.append(desc.serialize())
        if internal:
            result["internal"] = descriptors
        else:
            result["receive"] = descriptors

    return result

def displayaddress(client, path=None, desc=None, sh_wpkh=False, wpkh=False, redeem_script=None):
    if path is not None:
        if sh_wpkh and wpkh:
            return {'error': 'Both `--wpkh` and `--sh_wpkh` can not be selected at the same time.', 'code': BAD_ARGUMENT}
        return client.display_address(path, sh_wpkh, wpkh, redeem_script=redeem_script)
    elif desc is not None:
        if client.fingerprint is None:
            master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
            client.fingerprint = get_xpub_fingerprint_hex(master_xpub)

        if sh_wpkh or wpkh:
            return {'error': ' `--wpkh` and `--sh_wpkh` can not be combined with --desc', 'code': BAD_ARGUMENT}
        descriptor = Descriptor.parse(desc, client.is_testnet)
        if descriptor is None:
            return {'error': 'Unable to parse descriptor: ' + desc, 'code': BAD_ARGUMENT}
        if descriptor.m_path is None:
            return {'error': 'Descriptor missing origin info: ' + desc, 'code': BAD_ARGUMENT}
        if descriptor.origin_fingerprint != client.fingerprint:
            return {'error': 'Descriptor fingerprint does not match device: ' + desc, 'code': BAD_ARGUMENT}
        xpub = client.get_pubkey_at_path(descriptor.m_path_base)['xpub']
        if descriptor.base_key != xpub and descriptor.base_key != xpub_to_pub_hex(xpub):
            return {'error': 'Key in descriptor does not match device: ' + desc, 'code': BAD_ARGUMENT}
        return client.display_address(descriptor.m_path, descriptor.sh_wpkh, descriptor.wpkh)

def setup_device(client, label='', backup_passphrase=''):
    return client.setup_device(label, backup_passphrase)

def wipe_device(client):
    return client.wipe_device()

def restore_device(client, label):
    return client.restore_device(label)

def backup_device(client, label='', backup_passphrase=''):
    return client.backup_device(label, backup_passphrase)

def prompt_pin(client):
    return client.prompt_pin()

def send_pin(client, pin):
    return client.send_pin(pin)

def install_udev_rules(source, location):
    if platform.system() == "Linux":
        from .udevinstaller import UDevInstaller
        return UDevInstaller.install(source, location)
    return {'error': 'udev rules are not needed on your platform', 'code': NOT_IMPLEMENTED}
