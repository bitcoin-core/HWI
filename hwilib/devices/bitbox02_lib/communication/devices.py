# Copyright 2019 Shift Cryptosecurity AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""USB device utility functions"""

import re
from typing import List
from typing_extensions import TypedDict

import hid
import semver


BB02MULTI_BOOTLOADER = "bb02-bootloader"
BB02BTC_BOOTLOADER = "bb02btc-bootloader"
BITBOX02MULTI = "BitBox02"
BITBOX02BTC = "BitBox02BTC"


class TooManyFoundException(Exception):
    def __init__(self, count: int) -> None:
        super().__init__(f"Found {count} devices")


class NoneFoundException(Exception):
    def __init__(self) -> None:
        super().__init__("Found 0 devices")


class DeviceInfo(TypedDict):
    serial_number: str
    path: bytes
    product_string: str


def get_devices(product_string: str, interface_number: int = 0) -> List[DeviceInfo]:
    """
    Scans devices and returns a list of hid device info objects.
    """
    # TODO: product id is 0x2403, but 0x2402 is the id of some dev
    # device bootloaders. Can be removed in time, not needed for
    # production devices.
    # HWW/General endpoint is on interface 0
    # U2F Endpoint is on interface 1
    return [
        info
        for info in hid.enumerate()
        if info["vendor_id"] == 0x03EB
        and info["product_id"] in (0x2402, 0x2403)
        and (info["usage_page"] == 0xFFFF or info["interface_number"] == interface_number)
        and info["product_string"] == product_string
    ]


def get_device(product_string: str, interface_number: int = 0) -> DeviceInfo:
    devices = get_devices(product_string, interface_number)
    if len(devices) > 1:
        raise TooManyFoundException(len(devices))
    if not devices:
        raise NoneFoundException()
    return devices[0]


def get_bitbox02multi_device() -> DeviceInfo:
    return get_device(BITBOX02MULTI)


def get_bitbox02multi_bootloader() -> DeviceInfo:
    return get_device(BB02MULTI_BOOTLOADER)


def get_bitbox02btc_device() -> DeviceInfo:
    return get_device(BITBOX02BTC)


def get_bitbox02btc_bootloader() -> DeviceInfo:
    return get_device(BB02BTC_BOOTLOADER)


def get_bitbox02multi_devices() -> List[DeviceInfo]:
    return get_devices(BITBOX02MULTI)


def get_bitbox02multi_bootloaders() -> List[DeviceInfo]:
    return get_devices(BB02MULTI_BOOTLOADER)


def get_bitbox02btc_devices() -> List[DeviceInfo]:
    return get_devices(BITBOX02BTC)


def get_bitbox02btc_bootloaders() -> List[DeviceInfo]:
    return get_devices(BB02BTC_BOOTLOADER)


def get_any_bitbox02s() -> List[DeviceInfo]:
    """
    Searches for both btc-only and non-btc-only devices
    Returns:
        List of devices
    """
    devices = get_bitbox02multi_devices()
    devices.extend(get_bitbox02btc_devices())
    return devices


def get_any_bitbox02() -> DeviceInfo:
    """
    Searches for both btc-only and non-btc-only devices
    Raises:
        TooManyFoundException: If more than 1 is found
    Returns:
        A device if found, otherwise None
    """
    devices = get_any_bitbox02s()
    if len(devices) > 1:
        raise TooManyFoundException(len(devices))
    if not devices:
        raise NoneFoundException()
    return devices[0]


def get_any_bitbox02_bootloaders() -> List[DeviceInfo]:
    """
    Searches for both btc-only and non-btc-only devices
    Returns:
        List of devices
    """
    devices = get_bitbox02multi_bootloaders()
    devices.extend(get_bitbox02btc_bootloaders())
    return devices


def get_any_bitbox02_bootloader() -> DeviceInfo:
    """
    Searches for both btc-only and non-btc-only devices
    Raises:
        TooManyFoundException: If more than 1 is found
    Returns:
        A device if found, otherwise None
    """
    devices = get_any_bitbox02_bootloaders()
    if len(devices) > 1:
        raise TooManyFoundException(len(devices))
    if not devices:
        raise NoneFoundException
    return devices[0]


def parse_device_version(serial_number: str) -> semver.VersionInfo:
    match = re.search(r"v([0-9]+\.[0-9]+\.[0-9]+.*)", serial_number)
    if match is None:
        raise Exception(f"Could not parse version string from serial_number: {serial_number}")

    return semver.VersionInfo.parse(match.group(1))
