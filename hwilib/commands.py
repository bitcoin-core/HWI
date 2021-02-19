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
    BadArgumentError,
    NotImplementedError,
    UnknownDeviceError,
    UnavailableActionError,
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
from .common import Chain
from .hwwclient import HardwareWalletClient

from itertools import count
from typing import (
    Any,
    Dict,
    List,
    Optional,
)


py_enumerate = enumerate


# Get the client for the device
def get_client(device_type: str, device_path: str, password: str = "", expert: bool = False) -> Optional[HardwareWalletClient]:
    device_type = device_type.split('_')[0]
    class_name = device_type.capitalize()
    module = device_type.lower()

    client: Optional[HardwareWalletClient] = None
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
def enumerate(password: str = "") -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []

    for module in all_devs:
        try:
            imported_dev = importlib.import_module('.devices.' + module, __package__)
            result.extend(imported_dev.enumerate(password)) # type: ignore
        except ImportError:
            pass # Ignore ImportErrors, the user may not have all device dependencies installed
    return result

# Fingerprint or device type required
def find_device(
    password: str = "",
    device_type: Optional[str] = None,
    fingerprint: Optional[str] = None,
    expert: bool = False,
) -> Optional[HardwareWalletClient]:
    devices = enumerate(password)
    for d in devices:
        if device_type is not None and d['type'] != device_type and d['model'] != device_type:
            continue
        client = None
        try:
            assert isinstance(d["type"], str)
            assert isinstance(d["path"], str)
            client = get_client(d['type'], d['path'], password, expert)
            if client is None:
                raise Exception()

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

def getmasterxpub(client: HardwareWalletClient) -> Dict[str, str]:
    return {"xpub": client.get_master_xpub().to_string()}

def signtx(client: HardwareWalletClient, psbt: str) -> Dict[str, str]:
    # Deserialize the transaction
    tx = PSBT()
    tx.deserialize(psbt)
    return {"psbt": client.sign_tx(tx).serialize()}

def getxpub(client: HardwareWalletClient, path: str, expert: bool = False) -> Dict[str, Any]:
    xpub = client.get_pubkey_at_path(path)
    result: Dict[str, Any] = {"xpub": xpub.to_string()}
    if expert:
        result.update(xpub.get_printable_dict())
    return result

def signmessage(client: HardwareWalletClient, message: str, path: str) -> Dict[str, str]:
    return {"signature": client.sign_message(message, path)}

def getkeypool_inner(
    client: HardwareWalletClient,
    path: str,
    start: int,
    end: int,
    internal: bool = False,
    keypool: bool = True,
    account: int = 0,
    addr_type: AddressType = AddressType.WPKH
) -> List[Dict[str, Any]]:
    master_fpr = client.get_master_fingerprint_hex()

    desc = getdescriptor(client, master_fpr, path, internal, addr_type, account, start, end)

    if not isinstance(desc, Descriptor):
        return desc

    this_import: Dict[str, Any] = {}

    this_import['desc'] = desc.to_string()
    this_import['range'] = [start, end]
    this_import['timestamp'] = 'now'
    this_import['internal'] = internal
    this_import['keypool'] = keypool
    this_import['active'] = keypool
    this_import['watchonly'] = True
    return [this_import]

def getdescriptor(
    client: HardwareWalletClient,
    master_fpr: str,
    path: Optional[str] = None,
    internal: bool = False,
    addr_type: AddressType = AddressType.WPKH,
    account: int = 0,
    start: Optional[int] = None,
    end: Optional[int] = None
) -> Descriptor:
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
        if client.chain == Chain.MAIN:
            parsed_path.append(H_(0))
        else:
            parsed_path.append(H_(1))

        # Account
        parsed_path.append(H_(account))

        # Receive or change
        if internal:
            parsed_path.append(1)
        else:
            parsed_path.append(0)
    else:
        if path[0] != "m":
            raise BadArgumentError("Path must start with m/")
        if path[-1] != "*":
            raise BadArgumentError("Path must end with /*")
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
        client.xpub_cache[path_base] = client.get_pubkey_at_path(path_base).to_string()

    pubkey = PubkeyProvider(origin, client.xpub_cache.get(path_base, ""), path_suffix)
    if is_wpkh:
        return WPKHDescriptor(pubkey)
    elif is_sh_wpkh:
        return SHDescriptor(WPKHDescriptor(pubkey))
    else:
        return PKHDescriptor(pubkey)

def getkeypool(
    client: HardwareWalletClient,
    path: str,
    start: int,
    end: int,
    internal: bool = False,
    keypool: bool = True,
    account: int = 0,
    addr_type: AddressType = AddressType.PKH,
    addr_all: bool = False
) -> List[Dict[str, Any]]:

    addr_types = [addr_type]
    if addr_all:
        addr_types = list(AddressType)

    # When no specific path or internal-ness is specified, create standard types
    chains: List[Dict[str, Any]] = []
    if path is None and not internal:
        for addr_type in addr_types:
            for internal_addr in [False, True]:
                chains = chains + getkeypool_inner(client, None, start, end, internal_addr, keypool, account, addr_type)
        return chains
    else:
        assert len(addr_types) == 1
        return getkeypool_inner(client, path, start, end, internal, keypool, account, addr_types[0])


def getdescriptors(
    client: HardwareWalletClient,
    account: int = 0
) -> Dict[str, List[str]]:
    master_fpr = client.get_master_fingerprint_hex()

    result = {}

    for internal in [False, True]:
        descriptors = []
        for addr_type in (AddressType.PKH, AddressType.SH_WPKH, AddressType.WPKH):
            try:
                desc = getdescriptor(client, master_fpr=master_fpr, internal=internal, addr_type=addr_type, account=account)
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

def displayaddress(
    client: HardwareWalletClient,
    path: Optional[str] = None,
    desc: Optional[str] = None,
    addr_type: AddressType = AddressType.PKH
) -> Dict[str, str]:
    if path is not None:
        return {"address": client.display_singlesig_address(path, addr_type)}
    elif desc is not None:
        descriptor = parse_descriptor(desc)
        addr_type = AddressType.PKH
        is_sh = isinstance(descriptor, SHDescriptor)
        is_wsh = isinstance(descriptor, WSHDescriptor)
        if is_sh or is_wsh:
            assert descriptor.subdescriptor
            descriptor = descriptor.subdescriptor
            if isinstance(descriptor, WSHDescriptor):
                is_wsh = True
                assert descriptor.subdescriptor
                descriptor = descriptor.subdescriptor
            if isinstance(descriptor, MultisigDescriptor):
                if is_sh and is_wsh:
                    addr_type = AddressType.SH_WPKH
                elif not is_sh and is_wsh:
                    addr_type = AddressType.WPKH
                return {"address": client.display_multisig_address(descriptor.thresh, descriptor.pubkeys, addr_type)}
        is_wpkh = isinstance(descriptor, WPKHDescriptor)
        if isinstance(descriptor, PKHDescriptor) or is_wpkh:
            pubkey = descriptor.pubkeys[0]
            if pubkey.origin is None:
                raise BadArgumentError(f"Descriptor missing origin info: {desc}")
            if pubkey.origin.get_fingerprint_hex() != client.get_master_fingerprint_hex():
                raise BadArgumentError(f"Descriptor fingerprint does not match device: {desc}")
            xpub = client.get_pubkey_at_path(pubkey.origin.get_derivation_path()).to_string()
            if pubkey.pubkey != xpub and pubkey.pubkey != xpub_to_pub_hex(xpub):
                raise BadArgumentError(f"Key in descriptor does not match device: {desc}")
            if is_sh and is_wpkh:
                addr_type = AddressType.SH_WPKH
            elif not is_sh and is_wpkh:
                addr_type = AddressType.WPKH
            return {"address": client.display_singlesig_address(pubkey.get_full_derivation_path(0), addr_type)}
    raise BadArgumentError("Missing both path and descriptor")

def setup_device(client: HardwareWalletClient, label: str = "", backup_passphrase: str = "") -> Dict[str, bool]:
    return {"success": client.setup_device(label, backup_passphrase)}

def wipe_device(client: HardwareWalletClient) -> Dict[str, bool]:
    return {"success": client.wipe_device()}

def restore_device(client: HardwareWalletClient, label: str = "", word_count: int = 24) -> Dict[str, bool]:
    return {"success": client.restore_device(label, word_count)}

def backup_device(client: HardwareWalletClient, label: str = "", backup_passphrase: str = "") -> Dict[str, bool]:
    return {"success": client.backup_device(label, backup_passphrase)}

def prompt_pin(client: HardwareWalletClient) -> Dict[str, bool]:
    return {"success": client.prompt_pin()}

def send_pin(client: HardwareWalletClient, pin: str) -> Dict[str, bool]:
    return {"success": client.send_pin(pin)}

def toggle_passphrase(client: HardwareWalletClient) -> Dict[str, bool]:
    return {"success": client.toggle_passphrase()}

def install_udev_rules(source: str, location: str) -> Dict[str, bool]:
    if platform.system() == "Linux":
        from .udevinstaller import UDevInstaller
        return {"success": UDevInstaller.install(source, location)}
    raise NotImplementedError("udev rules are not needed on your platform")
