from typing import Any, List, Optional, Tuple, Union

from ...errors import BadArgumentError
from .features import contains_onekey_marker
from ..trezorlib.transport import hid, udp, webusb

ONEKEY_HID_IDS = {
    (0x1209, 0x53C0),
    (0x1209, 0x53C1),
    (0x1209, 0x4F4A),
    (0x1209, 0x4F4B),
}
ONEKEY_WEBUSB_IDS = ONEKEY_HID_IDS.copy()
ONEKEY_EXCLUSIVE_USB_IDS = {
    (0x1209, 0x4F4A),
    (0x1209, 0x4F4B),
}
ONEKEY_SIMULATOR_PATH = "127.0.0.1:54935"

Device = Union[hid.HidTransport, webusb.WebUsbTransport, udp.UdpTransport]


def get_usb_id(device: Any) -> Optional[Tuple[int, int]]:
    if hasattr(device, "device"):
        raw_device = device.device
        if isinstance(raw_device, dict):
            vendor_id = raw_device.get("vendor_id")
            product_id = raw_device.get("product_id")
            if vendor_id is not None and product_id is not None:
                return (vendor_id, product_id)

        if hasattr(raw_device, "getVendorID") and hasattr(raw_device, "getProductID"):
            return (raw_device.getVendorID(), raw_device.getProductID())

    return None


def is_onekey_device(usb_id: Optional[Tuple[int, int]], label: str, vendor: str) -> bool:
    if usb_id in ONEKEY_HID_IDS:
        return True

    label_lower = label.lower()
    vendor_lower = vendor.lower()
    return "onekey" in label_lower or "onekey" in vendor_lower


def is_onekey_transport(device: Any, usb_id: Optional[Tuple[int, int]]) -> bool:
    if isinstance(device, udp.UdpTransport):
        return True

    if usb_id in ONEKEY_EXCLUSIVE_USB_IDS:
        return True

    if hasattr(device, "device"):
        raw_device = device.device

        if isinstance(raw_device, dict):
            return contains_onekey_marker(raw_device.get("product_string")) or contains_onekey_marker(
                raw_device.get("manufacturer_string")
            )

        if hasattr(raw_device, "getProduct") and hasattr(raw_device, "getManufacturer"):
            try:
                return contains_onekey_marker(raw_device.getProduct()) or contains_onekey_marker(
                    raw_device.getManufacturer()
                )
            except Exception:
                return False

    return False


def enumerate_transports(allow_emulators: bool = False) -> List[Device]:
    devs = hid.HidTransport.enumerate(usb_ids=ONEKEY_HID_IDS)
    devs.extend(webusb.WebUsbTransport.enumerate(usb_ids=ONEKEY_WEBUSB_IDS))
    if allow_emulators:
        devs.extend(udp.UdpTransport.enumerate(ONEKEY_SIMULATOR_PATH))
    return devs


def get_path_transport(path: str) -> Device:
    for dev in enumerate_transports(allow_emulators=True):
        if path == dev.get_path():
            return dev
    raise BadArgumentError(f"Could not find device by path: {path}")
