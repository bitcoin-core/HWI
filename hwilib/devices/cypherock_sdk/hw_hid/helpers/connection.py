from typing import List, cast
from ...interfaces import IDevice

import hid

CYPHEROCK_VENDOR_ID = 0x3503
CYPHEROCK_PRODUCT_ID = 0x0103

def get_available_devices() -> List[IDevice]:
    result_device_list: List[IDevice] = []

    devices = hid.enumerate(CYPHEROCK_VENDOR_ID, CYPHEROCK_PRODUCT_ID)
    for d in devices:
        if d.get('path') is not None and d.get('serial_number') is not None:
            device_info = cast(
                IDevice,
                {
                    "path": d['path'].decode(),
                    "vendor_id": d['vendor_id'],
                    "product_id": d['product_id'],
                    "serial": d['serial_number'],
                    "type": 'cypherock',
                    "model": 'cypherock-x1',
                    "label": None,
                    "needs_pin_sent": False,
                    "needs_passphrase_sent": False,
                    "fingerprint": bytes.fromhex(d['serial_number']).hex(), # Using the serial number as the fingerprint for now
                }
            )
            result_device_list.append(device_info)

    return result_device_list
