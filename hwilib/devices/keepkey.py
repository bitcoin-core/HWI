"""
Keepkey
*******
"""

from ..common import Chain
from ..errors import (
    DEVICE_NOT_INITIALIZED,
    DeviceNotReadyError,
    common_err_msgs,
    handle_errors,
)
from .trezorlib import protobuf
from .trezorlib.transport import (
    hid,
    udp,
    webusb,
)
from .trezor import TrezorClient, HID_IDS, WEBUSB_IDS
from .trezorlib.mapping import DEFAULT_MAPPING
from .trezorlib.messages import (
    DebugLinkState,
    Features,
    ResetDevice,
)
from .trezorlib.models import TrezorModel

from typing import (
    Any,
    Dict,
    List,
    Optional,
)

py_enumerate = enumerate # Need to use the enumerate built-in but there's another function already named that

KEEPKEY_HID_IDS = {(0x2B24, 0x0001)}
KEEPKEY_WEBUSB_IDS = {(0x2B24, 0x0002)}
KEEPKEY_SIMULATOR_PATH = '127.0.0.1:11044'

HID_IDS.update(KEEPKEY_HID_IDS)
WEBUSB_IDS.update(KEEPKEY_WEBUSB_IDS)


class KeepkeyFeatures(Features): # type: ignore
    MESSAGE_WIRE_TYPE = 17
    FIELDS = {
        1: protobuf.Field("vendor", "string", repeated=False, required=False),
        2: protobuf.Field("major_version", "uint32", repeated=False, required=True),
        3: protobuf.Field("minor_version", "uint32", repeated=False, required=True),
        4: protobuf.Field("patch_version", "uint32", repeated=False, required=True),
        5: protobuf.Field("bootloader_mode", "bool", repeated=False, required=False),
        6: protobuf.Field("device_id", "string", repeated=False, required=False),
        7: protobuf.Field("pin_protection", "bool", repeated=False, required=False),
        8: protobuf.Field("passphrase_protection", "bool", repeated=False, required=False),
        9: protobuf.Field("language", "string", repeated=False, required=False),
        10: protobuf.Field("label", "string", repeated=False, required=False),
        12: protobuf.Field("initialized", "bool", repeated=False, required=False),
        13: protobuf.Field("revision", "bytes", repeated=False, required=False),
        14: protobuf.Field("bootloader_hash", "bytes", repeated=False, required=False),
        15: protobuf.Field("imported", "bool", repeated=False, required=False),
        16: protobuf.Field("unlocked", "bool", repeated=False, required=False),
        17: protobuf.Field("passphrase_cached", "bool", repeated=False, required=False),
        21: protobuf.Field("model", "string", repeated=False, required=False),
        22: protobuf.Field("firmware_variant", "string", repeated=False, required=False),
        23: protobuf.Field("firmware_hash", "bytes", repeated=False, required=False),
        24: protobuf.Field("no_backup", "bool", repeated=False, required=False),
    }

    def __init__(
        self,
        *,
        firmware_variant: Optional[str] = None,
        firmware_hash: Optional[bytes] = None,
        passphrase_cached: Optional[bool] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.passphrase_cached = passphrase_cached
        self.firmware_variant = firmware_variant
        self.firmware_hash = firmware_hash


class KeepkeyResetDevice(ResetDevice): # type: ignore
    MESSAGE_WIRE_TYPE = 14
    FIELDS = {
        1: protobuf.Field("display_random", "bool", repeated=False, required=False),
        2: protobuf.Field("strength", "uint32", repeated=False, required=False),
        3: protobuf.Field("passphrase_protection", "bool", repeated=False, required=False),
        4: protobuf.Field("pin_protection", "bool", repeated=False, required=False),
        5: protobuf.Field("language", "string", repeated=False, required=False),
        6: protobuf.Field("label", "string", repeated=False, required=False),
        7: protobuf.Field("no_backup", "bool", repeated=False, required=False),
        8: protobuf.Field("auto_lock_delay_ms", "uint32", repeated=False, required=False),
        9: protobuf.Field("u2f_counter", "uint32", repeated=False, required=False),
    }

    def __init__(
        self,
        *,
        auto_lock_delay_ms: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.auto_lock_delay_ms = auto_lock_delay_ms


class KeepkeyDebugLinkState(DebugLinkState): # type: ignore
    MESSAGE_WIRE_TYPE = 102
    FIELDS = {
        1: protobuf.Field("layout", "bytes", repeated=False, required=False),
        2: protobuf.Field("pin", "string", repeated=False, required=False),
        3: protobuf.Field("matrix", "string", repeated=False, required=False),
        4: protobuf.Field("mnemonic_secret", "bytes", repeated=False, required=False),
        5: protobuf.Field("node", "HDNodeType", repeated=False, required=False),
        6: protobuf.Field("passphrase_protection", "bool", repeated=False, required=False),
        7: protobuf.Field("reset_word", "string", repeated=False, required=False),
        8: protobuf.Field("reset_entropy", "bytes", repeated=False, required=False),
        9: protobuf.Field("recovery_fake_word", "string", repeated=False, required=False),
        10: protobuf.Field("recovery_word_pos", "uint32", repeated=False, required=False),
        11: protobuf.Field("recovery_cipher", "string", repeated=False, required=False),
        12: protobuf.Field("recovery_auto_completed_word", "string", repeated=False, required=False),
        13: protobuf.Field("firmware_hash", "bytes", repeated=False, required=False),
        14: protobuf.Field("storage_hash", "bytes", repeated=False, required=False),
    }

    def __init__(
        self,
        *,
        recovery_cipher: Optional[str] = None,
        recovery_auto_completed_word: Optional[str] = None,
        firmware_hash: Optional[bytes] = None,
        storage_hash: Optional[bytes] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.recovery_cipher = recovery_cipher
        self.recovery_auto_completed_word = recovery_auto_completed_word
        self.firmware_hash = firmware_hash
        self.storage_hash = storage_hash


class KeepkeyClient(TrezorClient):
    def __init__(self, path: str, password: Optional[str] = None, expert: bool = False, chain: Chain = Chain.MAIN) -> None:
        """
        The `KeepkeyClient` is a `HardwareWalletClient` for interacting with the Keepkey.

        As Keepkeys are clones of the Trezor 1, please refer to `TrezorClient` for documentation.
        """
        model = TrezorModel(
            name="K1-14M",
            internal_name="keepkey",
            minimum_version=(0, 0, 0),
            vendors=("keepkey.com"),
            usb_ids=(), # unused
            default_mapping=DEFAULT_MAPPING,
        )
        model.default_mapping.register(KeepkeyFeatures)
        model.default_mapping.register(KeepkeyResetDevice)
        if path.startswith("udp"):
            model.default_mapping.register(KeepkeyDebugLinkState)

        super(KeepkeyClient, self).__init__(path, password, expert, chain, KEEPKEY_HID_IDS, KEEPKEY_WEBUSB_IDS, KEEPKEY_SIMULATOR_PATH, model)
        self.type = 'Keepkey'

    def can_sign_taproot(self) -> bool:
        """
        The KeepKey does not support Taproot yet.

        :returns: False, always
        """
        return False


def enumerate(password: Optional[str] = None, expert: bool = False, chain: Chain = Chain.MAIN, allow_emulators: bool = False) -> List[Dict[str, Any]]:
    results = []
    devs = hid.HidTransport.enumerate(usb_ids=KEEPKEY_HID_IDS)
    devs.extend(webusb.WebUsbTransport.enumerate(usb_ids=KEEPKEY_WEBUSB_IDS))
    if allow_emulators:
        devs.extend(udp.UdpTransport.enumerate(KEEPKEY_SIMULATOR_PATH))
    for dev in devs:
        d_data: Dict[str, Any] = {}

        d_data['type'] = 'keepkey'
        d_data['model'] = 'keepkey'
        d_data['path'] = dev.get_path()

        client = None

        with handle_errors(common_err_msgs["enumerate"], d_data):
            client = KeepkeyClient(d_data['path'], password)
            try:
                client.client.refresh_features()
            except TypeError:
                continue
            if 'keepkey' not in client.client.features.vendor:
                continue

            d_data['label'] = client.client.features.label
            if d_data['path'].startswith('udp:'):
                d_data['model'] += '_simulator'

            d_data['needs_pin_sent'] = client.client.features.pin_protection and not client.client.features.unlocked
            d_data['needs_passphrase_sent'] = client.client.features.passphrase_protection # always need the passphrase sent for Keepkey if it has passphrase protection enabled
            if d_data['needs_pin_sent']:
                raise DeviceNotReadyError('Keepkey is locked. Unlock by using \'promptpin\' and then \'sendpin\'.')
            if d_data['needs_passphrase_sent'] and password is None:
                raise DeviceNotReadyError("Passphrase needs to be specified before the fingerprint information can be retrieved")
            if client.client.features.initialized:
                d_data['fingerprint'] = client.get_master_fingerprint().hex()
                d_data['needs_passphrase_sent'] = False # Passphrase is always needed for the above to have worked, so it's already sent
            else:
                d_data['error'] = 'Not initialized'
                d_data['code'] = DEVICE_NOT_INITIALIZED

        if client:
            client.close()

        results.append(d_data)
    return results
