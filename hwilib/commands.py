#! /usr/bin/env python3

"""
Commands
********

The functions in this module are the primary way to interact with hardware wallets.
Each function that takes a ``client`` uses a :class:`~hwilib.hwwclient.HardwareWalletClient`.
The functions then call public members of that client to retrieve the data needed.

Clients can be constructed using :func:`~find_device` or :func:`~get_client`.

The :func:`~enumerate` function returns information about what devices are available to be connected to.
These information can then be used with :func:`~find_device` or :func:`~get_client` to get a :class:`~hwilib.hwwclient.HardwareWalletClient`.

Note that this documentation does not specify every exception that can be raised.
Many exceptions are buried within the functions implemented by each device's :class:`~hwilib.hwwclient.HardwareWalletClient`.
For more information about the exceptions that those can raise, please see the specific client documentation.
"""

import importlib
import logging
import platform

from ._base58 import xpub_to_pub_hex, xpub_to_xonly_pub_hex
from .key import (
    get_bip44_purpose,
    get_bip44_chain,
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
    TRDescriptor,
    PKHDescriptor,
    PubkeyProvider,
    SHDescriptor,
    WPKHDescriptor,
    WSHDescriptor,
)
from .devices import __all__ as all_devs
from .common import (
    AddressType,
    Chain,
)
from .hwwclient import HardwareWalletClient
from .psbt import PSBT

from itertools import count
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Union,
)


py_enumerate = enumerate


# Get the client for the device
def get_client(device_type: str, device_path: str, password: str = "", expert: bool = False, chain: Chain = Chain.MAIN) -> Optional[HardwareWalletClient]:
    """
    Returns a HardwareWalletClient for the given device type at the device path

    :param device_type: The type of device
    :param device_path: The path specifying where the device can be accessed as returned by :func:`~enumerate`
    :param password: The password to use for this device
    :param expert: Whether the device should be opened in expert mode (prints more information for some commands)
    :param chain: The Chain this client will be using
    :return: A :class:`~hwilib.hwwclient.HardwareWalletClient` to interact with the device
    :raises: UnknownDeviceError: if the device type is not known by HWI
    """

    device_type = device_type.split('_')[0]
    class_name = device_type.capitalize()
    module = device_type.lower()

    client: Optional[HardwareWalletClient] = None
    try:
        imported_dev = importlib.import_module('.devices.' + module, __package__)
        client_constructor = getattr(imported_dev, class_name + 'Client')
        client = client_constructor(device_path, password, expert, chain)
    except ImportError:
        if client:
            client.close()
        raise UnknownDeviceError('Unknown device type specified')

    return client

# Get a list of all available hardware wallets
def enumerate(password: str = "") -> List[Dict[str, Any]]:
    """
    Enumerate all of the devices that HWI can potentially access.

    :param password: The password to use for devices which take passwords from the host.
    :return: A list of devices for which clients can be created for.
    """

    result: List[Dict[str, Any]] = []

    for module in all_devs:
        try:
            imported_dev = importlib.import_module('.devices.' + module, __package__)
            result.extend(imported_dev.enumerate(password)) # type: ignore
        except ImportError as e:
            # Warn for ImportErrors, but largely ignore them to allow users not install
            # all device dependencies if only one or some devices are wanted.
            logging.warn(f"{e}, required for {module}. Ignore if you do not want this device.")
            pass
    return result

# Fingerprint or device type required
def find_device(
    password: str = "",
    device_type: Optional[str] = None,
    fingerprint: Optional[str] = None,
    expert: bool = False,
    chain: Chain = Chain.MAIN,
) -> Optional[HardwareWalletClient]:
    """
    Find a device from the device type or fingerprint and get a client to access it.
    This is used as an alternative to :func:`~get_client` if the device path is not known.

    :param password: A password that may be needed to access the device if it can take passwords from the host
    :param device_type: The type of device. The client returned will be for this type of device.
        If not provided, the fingerprint must be provided
    :param fingerprint: The fingerprint of the master public key for the device.
        The client returned will have a master public key fingerprint matching this.
        If not provided, device_type must be provided.
    :param expert: Whether the device should be opened in expert mode (enables additional output for some actions)
    :param chain: The Chain this client will be using
    :return: A client to interact with the found device
    """

    devices = enumerate(password)
    for d in devices:
        if device_type is not None and d['type'] != device_type and d['model'] != device_type:
            continue
        client = None
        try:
            assert isinstance(d["type"], str)
            assert isinstance(d["path"], str)
            client = get_client(d['type'], d['path'], password, expert, chain)
            if client is None:
                raise Exception()

            if fingerprint:
                master_fpr = d.get('fingerprint', None)
                if master_fpr is None:
                    master_fpr = client.get_master_fingerprint().hex()

                if master_fpr != fingerprint:
                    client.close()
                    continue
            return client
        except Exception:
            if client:
                client.close()
            pass # Ignore things we wouldn't get fingerprints for
    return None

def getmasterxpub(client: HardwareWalletClient, addrtype: AddressType = AddressType.WIT, account: int = 0) -> Dict[str, str]:
    """
    Get the master extended public key from a client

    :param client: The client to interact with
    :return: A dictionary containing the public key at the ``m/44'/0'/0'`` derivation path.
        Returned as ``{"xpub": <xpub string>}``.
    """
    return {"xpub": client.get_master_xpub(addrtype, account).to_string()}

def signtx(client: HardwareWalletClient, psbt: str) -> Dict[str, Union[bool, str]]:
    """
    Sign a Partially Signed Bitcoin Transaction (PSBT) with the client.

    :param client: The client to interact with
    :param psbt: The PSBT to sign
    :return: A dictionary containing the processed PSBT serialized in Base64.
        Returned as ``{"psbt": <base64 psbt string>}``.
    """
    # Deserialize the transaction
    tx = PSBT()
    tx.deserialize(psbt)
    result = client.sign_tx(tx).serialize()
    return {"psbt": result, "signed": result != psbt}

def getxpub(client: HardwareWalletClient, path: str, expert: bool = False) -> Dict[str, Any]:
    """
    Get the master public key at a path from a client

    :param client: The client to interact with
    :param path: The derivation path for the public key to retrieve
    :param expert: Whether to provide more information intended for experts.
    :return: A dictionary containing the public key at the ``bip32_path``.
        With expert mode, the information contained within the xpub are decoded and displayed.
        Returned as ``{"xpub": <xpub string>}``.
    """
    xpub = client.get_pubkey_at_path(path)
    result: Dict[str, Any] = {"xpub": xpub.to_string()}
    if expert:
        result.update(xpub.get_printable_dict())
    return result

def signmessage(client: HardwareWalletClient, message: str, path: str) -> Dict[str, str]:
    """
    Sign a message using the key at the derivation path with the client.

    The message will be signed using the Bitcoin signed message standard used by Bitcoin Core.
    The message can be either a string which is then encoded to bytes, or bytes.

    :param client: The client to interact with
    :param message: The message to sign
    :param path: The derivation path for the key to sign with
    :return: A dictionary containing the signature.
        Returned as ``{"signature": <base64 signature string>}``.
    """
    return {"signature": client.sign_message(message, path)}

def getkeypool_inner(
    client: HardwareWalletClient,
    path: str,
    start: int,
    end: int,
    internal: bool = False,
    keypool: bool = True,
    account: int = 0,
    addr_type: AddressType = AddressType.WIT
) -> List[Dict[str, Any]]:
    """
    :meta private:

    Construct a single dictionary that specifies a single descriptor and the extra fields needed for ``importmulti`` or ``importdescriptors`` to import it.

    :param path: The derivation path for the key in the descriptor
    :param start: The start index of the range, inclusive
    :param end: The end index of the range, inclusive
    :param internal: Whether to specify this import is change
    :param keypool: Whether to specify this import should be added to the keypool
    :param account: The BIP 44 account to use if ``path`` is not specified
    :param addr_type: The type of address the descriptor should create
    """
    master_fpr = client.get_master_fingerprint()

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
    master_fpr: bytes,
    path: Optional[str] = None,
    internal: bool = False,
    addr_type: AddressType = AddressType.WIT,
    account: int = 0,
    start: Optional[int] = None,
    end: Optional[int] = None
) -> Descriptor:
    """
    Get a descriptor from the client.

    :param client: The client to interact with
    :param master_fpr: The hex string for the master fingerprint of the device to use in the descriptor
    :param path: The derivation path for the xpub from which additional keys will be derived.
    :param internal: Whether the dictionary should indicate that the descriptor should be for change addresses
    :param addr_type: The type of address the descriptor should create
    :param account: The BIP 44 account to use if ``path`` is not specified
    :param start: The start of the range to import, inclusive
    :param end: The end of the range to import, inclusive
    :return: The descriptor constructed given the above arguments and key fetched from the device
    :raises: BadArgumentError: if an argument is malformed or missing.
    """

    parsed_path = []
    if not path:
        # Purpose
        parsed_path.append(H_(get_bip44_purpose(addr_type)))

        # Coin type
        parsed_path.append(H_(get_bip44_chain(client.chain)))

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

    origin = KeyOriginInfo(master_fpr, parsed_path[:i])
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
    if addr_type is AddressType.LEGACY:
        return PKHDescriptor(pubkey)
    elif addr_type is AddressType.SH_WIT:
        return SHDescriptor(WPKHDescriptor(pubkey))
    elif addr_type is AddressType.WIT:
        return WPKHDescriptor(pubkey)
    elif addr_type is AddressType.TAP:
        if not client.can_sign_taproot():
            raise UnavailableActionError("Device does not support Taproot")
        return TRDescriptor(pubkey)
    else:
        raise ValueError("Unknown address type")

def getkeypool(
    client: HardwareWalletClient,
    path: str,
    start: int,
    end: int,
    internal: bool = False,
    keypool: bool = True,
    account: int = 0,
    addr_type: AddressType = AddressType.WIT,
    addr_all: bool = False
) -> List[Dict[str, Any]]:
    """
    Get a dictionary which can be passed to Bitcoin Core's ``importmulti`` or ``importdescriptors`` RPCs to import a watchonly wallet based on the client.
    By default, a descriptor for legacy addresses is returned.

    :param client: The client to interact with
    :param path: The derivation path for the xpub from which additional keys will be derived.
    :param start: The start of the range to import, inclusive
    :param end: The end of the range to import, inclusive
    :param internal: Whether the dictionary should indicate that the descriptor should be for change addresses
    :param keypool: Whether the dictionary should indicate that the dsecriptor should be added to the Bitcoin Core keypool/addresspool
    :param account: The BIP 44 account to use if ``path`` is not specified
    :param addr_type: The address type
    :param addr_all: Whether to return a multiple descriptors for every address type
    :return: The dictionary containing the descriptor and all of the arguments for ``importmulti`` or ``importdescriptors``
    :raises: BadArgumentError: if an argument is malformed or missing.
    """
    supports_taproot = client.can_sign_taproot()

    addr_types = [addr_type]
    if addr_all:
        addr_types = list(AddressType)
    elif not supports_taproot and addr_type == AddressType.TAP:
        raise UnavailableActionError("Device does not support Taproot")

    if not supports_taproot and AddressType.TAP in addr_types:
        del addr_types[addr_types.index(AddressType.TAP)]

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
    """
    Get descriptors from the client.

    :param client: The client to interact with
    :param account: The BIP 44 account to use
    :return: Multiple descriptors from the device matching the BIP 44 standard paths and the given ``account``.
    :raises: BadArgumentError: if an argument is malformed or missing.
    """
    master_fpr = client.get_master_fingerprint()

    result = {}

    for internal in [False, True]:
        descriptors = []
        for addr_type in list(AddressType):
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
    addr_type: AddressType = AddressType.WIT
) -> Dict[str, str]:
    """
    Display an address on the device for client.
    The address can be specified by the path with additional parameters, or by a descriptor.

    :param client: The client to interact with
    :param path: The path of the address to display. Mutually exclusive with ``desc``
    :param desc: The descriptor to display the address for. Mutually exclusive with ``path``
    :param addr_type: The address type to return. Only works with ``path``
    :return: A dictionary containing the address displayed.
        Returned as ``{"address": <base58 or bech32 address string>}``.
    :raises: BadArgumentError: if an argument is malformed, missing, or conflicts.
    """
    if path is not None:
        return {"address": client.display_singlesig_address(path, addr_type)}
    elif desc is not None:
        descriptor = parse_descriptor(desc)
        addr_type = AddressType.LEGACY
        is_sh = isinstance(descriptor, SHDescriptor)
        is_wsh = isinstance(descriptor, WSHDescriptor)
        if is_sh or is_wsh:
            assert len(descriptor.subdescriptors) == 1
            descriptor = descriptor.subdescriptors[0]
            if isinstance(descriptor, WSHDescriptor):
                is_wsh = True
                assert len(descriptor.subdescriptors) == 1
                descriptor = descriptor.subdescriptors[0]
            if isinstance(descriptor, MultisigDescriptor):
                if is_sh and is_wsh:
                    addr_type = AddressType.SH_WIT
                elif not is_sh and is_wsh:
                    addr_type = AddressType.WIT
                return {"address": client.display_multisig_address(addr_type, descriptor)}
        is_wpkh = isinstance(descriptor, WPKHDescriptor)
        if isinstance(descriptor, PKHDescriptor) or is_wpkh or isinstance(descriptor, TRDescriptor):
            pubkey = descriptor.pubkeys[0]
            if pubkey.origin is None:
                raise BadArgumentError(f"Descriptor missing origin info: {desc}")
            if pubkey.origin.fingerprint != client.get_master_fingerprint():
                raise BadArgumentError(f"Descriptor fingerprint does not match device: {desc}")
            xpub = client.get_pubkey_at_path(pubkey.origin.get_derivation_path()).to_string()
            if pubkey.pubkey != xpub and pubkey.pubkey != xpub_to_pub_hex(xpub) and pubkey.pubkey != xpub_to_xonly_pub_hex(xpub):
                raise BadArgumentError(f"Key in descriptor does not match device: {desc}")
            if is_sh and is_wpkh:
                addr_type = AddressType.SH_WIT
            elif not is_sh and is_wpkh:
                addr_type = AddressType.WIT
            elif isinstance(descriptor, TRDescriptor):
                addr_type = AddressType.TAP
            return {"address": client.display_singlesig_address(pubkey.get_full_derivation_path(0), addr_type)}
    raise BadArgumentError("Missing both path and descriptor")

def setup_device(client: HardwareWalletClient, label: str = "", backup_passphrase: str = "") -> Dict[str, bool]:
    """
    Setup a device that has not yet been initialized.

    :param client: The client to interact with
    :param label: The label to apply to the newly setup device
    :param backup_passphrase: The passphrase to use for the backup, if backups are encrypted for that device
    :return: A dictionary with the ``success`` key.
    """
    return {"success": client.setup_device(label, backup_passphrase)}

def wipe_device(client: HardwareWalletClient) -> Dict[str, bool]:
    """
    Wipe a device

    :param client: The client to interact with
    :return: A dictionary with the ``success`` key.
    """
    return {"success": client.wipe_device()}

def restore_device(client: HardwareWalletClient, label: str = "", word_count: int = 24) -> Dict[str, bool]:
    """
    Restore a backup to a device that has not yet been initialized.

    :param client: The client to interact with
    :param label: The label to apply to the newly setup device
    :param word_count: The number of words in the recovery phrase
    :return: A dictionary with the ``success`` key.
    """
    return {"success": client.restore_device(label, word_count)}

def backup_device(client: HardwareWalletClient, label: str = "", backup_passphrase: str = "") -> Dict[str, bool]:
    """
    Create a backup of the device

    :param client: The client to interact with
    :param label: The label to apply to the newly setup device
    :param backup_passphrase: The passphrase to use for the backup, if backups are encrypted for that device
    :return: A dictionary with the ``success`` key.
    """
    return {"success": client.backup_device(label, backup_passphrase)}

def prompt_pin(client: HardwareWalletClient) -> Dict[str, bool]:
    """
    Trigger the device to show the setup for PIN entry.

    :param client: The client to interact with
    :return: A dictionary with the ``success`` key.
    """
    return {"success": client.prompt_pin()}

def send_pin(client: HardwareWalletClient, pin: str) -> Dict[str, bool]:
    """
    Send a PIN to the device after :func:`prompt_pin` has been called.

    :param client: The client to interact with
    :param pin: The PIN to send
    :return: A dictionary with the ``success`` key.
    """
    return {"success": client.send_pin(pin)}

def toggle_passphrase(client: HardwareWalletClient) -> Dict[str, bool]:
    """
    Toggle whether the device is using a BIP 39 passphrase.

    :param client: The client to interact with
    :return: A dictionary with the ``success`` key.
    """
    return {"success": client.toggle_passphrase()}

def install_udev_rules(source: str, location: str) -> Dict[str, bool]:
    """
    Install the udev rules to the local machine.
    The rules will be copied from the source to the location.
    ``udevadm`` will also be triggered and the rules reloaded so that the devices can be plugged in and used immediately.
    A ``plugdev`` group will also be created if it does not exist and the user will be added to it.

    The recommended source location is ``hwilib/udev``. The recommended destination location is ``/etc/udev/rules.d``

    This function is equivalent to::

        sudo cp hwilib/udev/*rules /etc/udev/rules.d/
        sudo udevadm trigger
        sudo udevadm control --reload-rules
        sudo groupadd plugdev
        sudo usermod -aG plugdev `whoami`

    :param source: The directory containing the udev rules to install
    :param location: The directory to install the udev rules to
    :return: A dictionary with the ``success`` key.
    :raises: NotImplementedError: if udev rules cannot be installed on this system, i.e. it is not linux.
    """
    if platform.system() == "Linux":
        from .udevinstaller import UDevInstaller
        return {"success": UDevInstaller.install(source, location)}
    raise NotImplementedError("udev rules are not needed on your platform")
