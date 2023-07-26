# type: ignore
""""
OneKey Devices
**************
"""


import sys
from ..common import Chain
from ..errors import (
    DEVICE_NOT_INITIALIZED,
    DeviceNotReadyError,
    common_err_msgs,
    handle_errors,
)
from .trezorlib import protobuf
from .trezorlib.transport import (
    udp,
    webusb,
)
from .trezor import TrezorClient
from .trezorlib.mapping import DEFAULT_MAPPING
from .trezorlib.messages import (
    BackupType,
    Capability,
    Features,
    SafetyCheckLevel,
)
from types import MethodType
from .trezorlib.models import TrezorModel
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Sequence,
)

py_enumerate = enumerate  # Need to use the enumerate built-in but there's another function already named that

VENDORS = ("onekey.so", "trezor.io",)


class OnekeyFeatures(Features):
    MESSAGE_WIRE_TYPE = 17
    FIELDS = {
        1: protobuf.Field("vendor", "string", repeated=False, required=False),
        2: protobuf.Field("major_version", "uint32", repeated=False, required=True),
        3: protobuf.Field("minor_version", "uint32", repeated=False, required=True),
        4: protobuf.Field("patch_version", "uint32", repeated=False, required=True),
        5: protobuf.Field("bootloader_mode", "bool", repeated=False, required=False),
        6: protobuf.Field("device_id", "string", repeated=False, required=False),
        7: protobuf.Field("pin_protection", "bool", repeated=False, required=False),
        8: protobuf.Field(
            "passphrase_protection", "bool", repeated=False, required=False
        ),
        9: protobuf.Field("language", "string", repeated=False, required=False),
        10: protobuf.Field("label", "string", repeated=False, required=False),
        12: protobuf.Field("initialized", "bool", repeated=False, required=False),
        13: protobuf.Field("revision", "bytes", repeated=False, required=False),
        14: protobuf.Field("bootloader_hash", "bytes", repeated=False, required=False),
        15: protobuf.Field("imported", "bool", repeated=False, required=False),
        16: protobuf.Field("unlocked", "bool", repeated=False, required=False),
        17: protobuf.Field(
            "_passphrase_cached", "bool", repeated=False, required=False
        ),
        18: protobuf.Field("firmware_present", "bool", repeated=False, required=False),
        19: protobuf.Field("needs_backup", "bool", repeated=False, required=False),
        20: protobuf.Field("flags", "uint32", repeated=False, required=False),
        21: protobuf.Field("model", "string", repeated=False, required=False),
        22: protobuf.Field("fw_major", "uint32", repeated=False, required=False),
        23: protobuf.Field("fw_minor", "uint32", repeated=False, required=False),
        24: protobuf.Field("fw_patch", "uint32", repeated=False, required=False),
        25: protobuf.Field("fw_vendor", "string", repeated=False, required=False),
        27: protobuf.Field("unfinished_backup", "bool", repeated=False, required=False),
        28: protobuf.Field("no_backup", "bool", repeated=False, required=False),
        29: protobuf.Field("recovery_mode", "bool", repeated=False, required=False),
        30: protobuf.Field("capabilities", "Capability", repeated=True, required=False),
        31: protobuf.Field("backup_type", "BackupType", repeated=False, required=False),
        32: protobuf.Field("sd_card_present", "bool", repeated=False, required=False),
        33: protobuf.Field("sd_protection", "bool", repeated=False, required=False),
        34: protobuf.Field(
            "wipe_code_protection", "bool", repeated=False, required=False
        ),
        35: protobuf.Field("session_id", "bytes", repeated=False, required=False),
        36: protobuf.Field(
            "passphrase_always_on_device", "bool", repeated=False, required=False
        ),
        37: protobuf.Field(
            "safety_checks", "SafetyCheckLevel", repeated=False, required=False
        ),
        38: protobuf.Field(
            "auto_lock_delay_ms", "uint32", repeated=False, required=False
        ),
        39: protobuf.Field(
            "display_rotation", "uint32", repeated=False, required=False
        ),
        40: protobuf.Field(
            "experimental_features", "bool", repeated=False, required=False
        ),
        500: protobuf.Field("offset", "uint32", repeated=False, required=False),
        501: protobuf.Field("ble_name", "string", repeated=False, required=False),
        502: protobuf.Field("ble_ver", "string", repeated=False, required=False),
        503: protobuf.Field("ble_enable", "bool", repeated=False, required=False),
        504: protobuf.Field("se_enable", "bool", repeated=False, required=False),
        506: protobuf.Field("se_ver", "string", repeated=False, required=False),
        507: protobuf.Field("backup_only", "bool", repeated=False, required=False),
        508: protobuf.Field("onekey_version", "string", repeated=False, required=False),
        509: protobuf.Field("onekey_serial", "string", repeated=False, required=False),
        510: protobuf.Field(
            "bootloader_version", "string", repeated=False, required=False
        ),
        511: protobuf.Field("serial_no", "string", repeated=False, required=False),
        519: protobuf.Field(
            "boardloader_version", "string", repeated=False, required=False
        ),
    }

    def __init__(
        self,
        *,
        major_version: "int",
        minor_version: "int",
        patch_version: "int",
        capabilities: Optional[Sequence["Capability"]] = None,
        vendor: Optional["str"] = None,
        bootloader_mode: Optional["bool"] = None,
        device_id: Optional["str"] = None,
        pin_protection: Optional["bool"] = None,
        passphrase_protection: Optional["bool"] = None,
        language: Optional["str"] = None,
        label: Optional["str"] = None,
        initialized: Optional["bool"] = None,
        revision: Optional["bytes"] = None,
        bootloader_hash: Optional["bytes"] = None,
        imported: Optional["bool"] = None,
        unlocked: Optional["bool"] = None,
        _passphrase_cached: Optional["bool"] = None,
        firmware_present: Optional["bool"] = None,
        needs_backup: Optional["bool"] = None,
        flags: Optional["int"] = None,
        model: Optional["str"] = None,
        fw_major: Optional["int"] = None,
        fw_minor: Optional["int"] = None,
        fw_patch: Optional["int"] = None,
        fw_vendor: Optional["str"] = None,
        unfinished_backup: Optional["bool"] = None,
        no_backup: Optional["bool"] = None,
        recovery_mode: Optional["bool"] = None,
        backup_type: Optional["BackupType"] = None,
        sd_card_present: Optional["bool"] = None,
        sd_protection: Optional["bool"] = None,
        wipe_code_protection: Optional["bool"] = None,
        session_id: Optional["bytes"] = None,
        passphrase_always_on_device: Optional["bool"] = None,
        safety_checks: Optional["SafetyCheckLevel"] = None,
        auto_lock_delay_ms: Optional["int"] = None,
        display_rotation: Optional["int"] = None,
        experimental_features: Optional["bool"] = None,
        offset: Optional["int"] = None,
        ble_name: Optional["str"] = None,
        ble_ver: Optional["str"] = None,
        ble_enable: Optional["bool"] = None,
        se_enable: Optional["bool"] = None,
        se_ver: Optional["str"] = None,
        backup_only: Optional["bool"] = None,
        onekey_version: Optional["str"] = None,
        onekey_serial: Optional["str"] = None,
        bootloader_version: Optional["str"] = None,
        serial_no: Optional["str"] = None,
        boardloader_version: Optional["str"] = None,
    ) -> None:
        self.capabilities: Sequence["Capability"] = (
            capabilities if capabilities is not None else []
        )
        self.major_version = major_version
        self.minor_version = minor_version
        self.patch_version = patch_version
        self.vendor = vendor
        self.bootloader_mode = bootloader_mode
        self.device_id = device_id
        self.pin_protection = pin_protection
        self.passphrase_protection = passphrase_protection
        self.language = language
        self.label = label
        self.initialized = initialized
        self.revision = revision
        self.bootloader_hash = bootloader_hash
        self.imported = imported
        self.unlocked = unlocked
        self._passphrase_cached = _passphrase_cached
        self.firmware_present = firmware_present
        self.needs_backup = needs_backup
        self.flags = flags
        self.model = model
        self.fw_major = fw_major
        self.fw_minor = fw_minor
        self.fw_patch = fw_patch
        self.fw_vendor = fw_vendor
        self.unfinished_backup = unfinished_backup
        self.no_backup = no_backup
        self.recovery_mode = recovery_mode
        self.backup_type = backup_type
        self.sd_card_present = sd_card_present
        self.sd_protection = sd_protection
        self.wipe_code_protection = wipe_code_protection
        self.session_id = session_id
        self.passphrase_always_on_device = passphrase_always_on_device
        self.safety_checks = safety_checks
        self.auto_lock_delay_ms = auto_lock_delay_ms
        self.display_rotation = display_rotation
        self.experimental_features = experimental_features
        self.offset = offset
        self.ble_name = ble_name
        self.ble_ver = ble_ver
        self.ble_enable = ble_enable
        self.se_enable = se_enable
        self.se_ver = se_ver
        self.backup_only = backup_only
        self.onekey_version = onekey_version
        self.onekey_serial = onekey_serial
        self.bootloader_version = bootloader_version
        self.serial_no = serial_no
        self.boardloader_version = boardloader_version


ONEKEY_MAPPING = DEFAULT_MAPPING.register(OnekeyFeatures)

USB_IDS = {(0x1209, 0x4F4A), (0x1209, 0x4F4B), (0x1209, 0x53C1)}

ONEKEY_LEGACY = TrezorModel(
    name="1",
    minimum_version=(2, 11, 0),
    vendors=VENDORS,
    usb_ids=USB_IDS,
    default_mapping=ONEKEY_MAPPING,
)

ONEKEY_TOUCH = TrezorModel(
    name="T",
    minimum_version=(4, 2, 0),
    vendors=VENDORS,
    usb_ids=USB_IDS,
    default_mapping=ONEKEY_MAPPING,
)

ONEKEYS = (ONEKEY_LEGACY, ONEKEY_TOUCH)


def model_by_name(name: str) -> Optional[TrezorModel]:
    for model in ONEKEYS:
        if model.name == name:
            return model
    return None


# ===============overwrite methods for onekey device begin============


def _refresh_features(self: object, features: Features) -> None:
    """Update internal fields based on passed-in Features message."""
    if not self.model:
        self.model = model_by_name(features.model or "1")
        if self.model is None:
            raise RuntimeError("Unsupported OneKey model")

    if features.vendor not in self.model.vendors:
        raise RuntimeError("Unsupported device")
    self.features = features
    self.version = self.features.onekey_version
    self.check_firmware_version(warn_only=True)
    if self.features.session_id is not None:
        self.session_id = self.features.session_id
        self.features.session_id = None


def is_outdated(self: object) -> bool:
    if self.features.bootloader_mode:
        return False

    assert self.model is not None  # should happen in _refresh_features
    return self.version < ".".join(map(str, self.model.minimum_version))


def button_request(self: object, code: Optional[int]) -> None:
    if not self.prompt_shown:
        print("Please confirm action on your OneKey device", file=sys.stderr)
    if not self.always_prompt:
        self.prompt_shown = True


# ===============overwrite methods for onekey device end============


class OnekeyClient(TrezorClient):
    def __init__(
        self,
        path: str,
        password: Optional[str] = None,
        expert: bool = False,
        chain: Chain = Chain.MAIN,
    ) -> None:
        super().__init__(path, password, expert, chain, webusb_ids=USB_IDS)
        self.client._refresh_features = MethodType(_refresh_features, self.client)
        self.client.is_outdated = MethodType(is_outdated, self.client)
        self.client.ui.button_request = MethodType(button_request, self.client.ui)
        self.type = "OneKey"


def enumerate(
    password: Optional[str] = None, expert: bool = False, chain: Chain = Chain.MAIN
) -> List[Dict[str, Any]]:
    results = []
    devs = webusb.WebUsbTransport.enumerate(usb_ids=USB_IDS)
    devs.extend(udp.UdpTransport.enumerate())
    for dev in devs:
        d_data: Dict[str, Any] = {}

        d_data["type"] = "onekey"
        d_data["path"] = dev.get_path()
        client = None
        with handle_errors(common_err_msgs["enumerate"], d_data, debug=True):
            client = OnekeyClient(d_data["path"], password)
            try:
                client._prepare_device()
            except TypeError:
                import traceback

                traceback.print_exc()
                continue
            if not client.client.features.onekey_version or client.client.features.vendor not in VENDORS:
                continue

            d_data["label"] = client.client.features.label
            d_data["model"] = "onekey_" + client.client.features.model.lower()
            if d_data["path"].startswith("udp:"):
                d_data["model"] += "_simulator"

            d_data["needs_pin_sent"] = (
                client.client.features.pin_protection
                and not client.client.features.unlocked
            )
            if client.client.features.model == "1":
                d_data[
                    "needs_passphrase_sent"
                ] = (
                    client.client.features.passphrase_protection
                )  # always need the passphrase sent for Trezor One if it has passphrase protection enabled
            else:
                d_data["needs_passphrase_sent"] = False
            if d_data["needs_pin_sent"]:
                raise DeviceNotReadyError(
                    "OneKey is locked. Unlock by using 'promptpin' and then 'sendpin'."
                )
            if d_data["needs_passphrase_sent"] and password is None:
                d_data["warnings"] = [
                    [
                        'Passphrase protection enabled but passphrase was not provided. Using default passphrase of the empty string ("")'
                    ]
                ]
            if client.client.features.initialized:
                d_data["fingerprint"] = client.get_master_fingerprint().hex()
                d_data[
                    "needs_passphrase_sent"
                ] = False  # Passphrase is always needed for the above to have worked, so it's already sent
            else:
                d_data["error"] = "Not initialized"
                d_data["code"] = DEVICE_NOT_INITIALIZED

        if client:
            client.close()

        results.append(d_data)
    return results
