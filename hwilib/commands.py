#! /usr/bin/env python3

# Hardware wallet interaction script

import binascii
import importlib
import platform

from .serializations import AddressType, PSBT
from .base58 import xpub_to_pub_hex
from .key import (
    H_,
    HARDENED_FLAG,
    is_hardened,
    KeyOriginInfo,
    parse_path,
)
from .errors import (
    UnknownDeviceError,
    UnavailableActionError,
    BAD_ARGUMENT,
    NOT_IMPLEMENTED,
)
from .descriptor import (
    Descriptor,
    parse_descriptor,
    MultisigDescriptor,
    PKHDescriptor,
    PubkeyProvider,
    SHDescriptor,
    WPKHDescriptor,
    WSHDescriptor,
)
from .devices import __all__ as all_devs

from itertools import count

py_enumerate = enumerate


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

            if fingerprint:
                master_fpr = d.get('fingerprint', None)
                if master_fpr is None:
                    master_fpr = client.get_master_fingerprint_hex()

                if master_fpr != fingerprint:
                    client.close()
                    continue
            return client
        except Exception:
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

    this_import['desc'] = desc.to_string()
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

    parsed_path = []
    if not path:
        # Purpose
        if is_wpkh:
            parsed_path.append(H_(84))
        elif is_sh_wpkh:
            parsed_path.append(H_(49))
        else:
            assert addr_type == AddressType.PKH
            parsed_path.append(H_(44))

        # Coin type
        if testnet:
            parsed_path.append(H_(1))
        else:
            parsed_path.append(H_(0))

        # Account
        parsed_path.append(H_(account))

        # Receive or change
        if internal:
            parsed_path.append(1)
        else:
            parsed_path.append(0)
    else:
        if path[0] != "m":
            return {'error': 'Path must start with m/', 'code': BAD_ARGUMENT}
        if path[-1] != "*":
            return {'error': 'Path must end with /*', 'code': BAD_ARGUMENT}
        parsed_path = parse_path(path[:-2])

    # Find the last hardened derivation:
    for i, p in zip(count(len(parsed_path) - 1, -1), reversed(parsed_path)):
        if is_hardened(p):
            break
    i += 1

    origin = KeyOriginInfo(binascii.unhexlify(master_fpr), parsed_path[:i])
    path_base = origin.get_derivation_path()

    path_suffix = ""
    for p in parsed_path[i:]:
        hardened = is_hardened(p)
        p &= ~HARDENED_FLAG
        path_suffix += "/{}{}".format(p, "h" if hardened else "")
    path_suffix += "/*"

    # Get the key at the base
    if client.xpub_cache.get(path_base) is None:
        client.xpub_cache[path_base] = client.get_pubkey_at_path(path_base)['xpub']

    pubkey = PubkeyProvider(origin, client.xpub_cache.get(path_base), path_suffix)
    if is_wpkh:
        return WPKHDescriptor(pubkey)
    elif is_sh_wpkh:
        return SHDescriptor(WPKHDescriptor(pubkey))
    else:
        return PKHDescriptor(pubkey)

def getkeypool(client, path, start, end, internal=False, keypool=True, account=0, addr_type: AddressType = AddressType.PKH, addr_all=False):

    addr_types = [addr_type]
    if addr_all:
        addr_types = list(AddressType)

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
        for addr_type in (AddressType.PKH, AddressType.SH_WPKH, AddressType.WPKH):
            try:
                desc = getdescriptor(client, master_fpr=master_fpr, testnet=client.is_testnet, internal=internal, addr_type=addr_type, account=account)
            except UnavailableActionError:
                # Device does not support this address type or network. Skip.
                continue
            if not isinstance(desc, Descriptor):
                return desc
            descriptors.append(desc.to_string())
        if internal:
            result["internal"] = descriptors
        else:
            result["receive"] = descriptors

    return result

def displayaddress(client, path=None, desc=None, addr_type: AddressType = AddressType.PKH):
    if path is not None:
        return client.display_singlesig_address(path, addr_type)
    elif desc is not None:
        descriptor = parse_descriptor(desc)
        addr_type = AddressType.PKH
        is_sh = isinstance(descriptor, SHDescriptor)
        is_wsh = isinstance(descriptor, WSHDescriptor)
        if is_sh or is_wsh:
            descriptor = descriptor.subdescriptor
            if isinstance(descriptor, WSHDescriptor):
                is_wsh = True
                descriptor = descriptor.subdescriptor
            if isinstance(descriptor, MultisigDescriptor):
                if is_sh and is_wsh:
                    addr_type = AddressType.SH_WPKH
                elif not is_sh and is_wsh:
                    addr_type = AddressType.WPKH
                return client.display_multisig_address(descriptor.thresh, descriptor.pubkeys, addr_type)
        is_wpkh = isinstance(descriptor, WPKHDescriptor)
        if isinstance(descriptor, PKHDescriptor) or is_wpkh:
            pubkey = descriptor.pubkeys[0]
            if pubkey.origin is None:
                return {'error': 'Descriptor missing origin info: ' + desc, 'code': BAD_ARGUMENT}
            if pubkey.origin.get_fingerprint_hex() != client.get_master_fingerprint_hex():
                return {'error': 'Descriptor fingerprint does not match device: ' + desc, 'code': BAD_ARGUMENT}
            xpub = client.get_pubkey_at_path(pubkey.origin.get_derivation_path())['xpub']
            if pubkey.pubkey != xpub and pubkey.pubkey != xpub_to_pub_hex(xpub):
                return {'error': 'Key in descriptor does not match device: ' + desc, 'code': BAD_ARGUMENT}
            if is_sh and is_wpkh:
                addr_type = AddressType.SH_WPKH
            elif not is_sh and is_wpkh:
                addr_type = AddressType.WPKH
            return client.display_singlesig_address(pubkey.get_full_derivation_path(0), addr_type)

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
