from . import _patch  # noqa: F401 — patches trezorlib on import
from .messages import OneKeyDeviceType
from .client import (
    OneKeyDebugLinkClient,
    OneKeyTransportClient,
    PASSPHRASE_ON_DEVICE,
    PassphraseUI,
)
from .features import (
    contains_onekey_marker,
    is_onekey_features,
    locked_instructions,
    uses_host_pin,
)
from .protocol import (
    ONEKEY_DEVICE_TYPE_MODELS,
    OneKeyProfile,
    get_model,
    normalize_model,
    resolve_profile,
    resolve_profile_name,
    resolve_trezor_model,
)
from .transport import (
    Device,
    ONEKEY_EXCLUSIVE_USB_IDS,
    ONEKEY_HID_IDS,
    ONEKEY_SIMULATOR_PATH,
    ONEKEY_WEBUSB_IDS,
    enumerate_transports,
    get_path_transport,
    get_usb_id,
    is_onekey_device,
    is_onekey_transport,
)

__all__ = [
    "Device",
    "OneKeyDeviceType",
    "ONEKEY_DEVICE_TYPE_MODELS",
    "ONEKEY_EXCLUSIVE_USB_IDS",
    "ONEKEY_HID_IDS",
    "ONEKEY_SIMULATOR_PATH",
    "ONEKEY_WEBUSB_IDS",
    "OneKeyDebugLinkClient",
    "OneKeyProfile",
    "OneKeyTransportClient",
    "PASSPHRASE_ON_DEVICE",
    "PassphraseUI",
    "contains_onekey_marker",
    "enumerate_transports",
    "get_model",
    "get_path_transport",
    "get_usb_id",
    "is_onekey_device",
    "is_onekey_features",
    "is_onekey_transport",
    "locked_instructions",
    "normalize_model",
    "resolve_profile",
    "resolve_profile_name",
    "resolve_trezor_model",
    "uses_host_pin",
]
