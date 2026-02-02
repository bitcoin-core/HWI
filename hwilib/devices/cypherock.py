"""
Cypherock X1
************
"""

import hid

from typing import (
    Any,
    Dict,
    List,
    Optional,
)
from ..common import (
    Chain,
)

CYPHEROCK_VENDOR_ID = 0x3503
CYPHEROCK_PRODUCT_ID = 0x0103

def enumerate(password: Optional[str] = None, expert: bool = False, chain: Chain = Chain.MAIN, allow_emulators: bool = False) -> List[Dict[str, Any]]:
    results = []
    devices = []
    devices.extend(hid.enumerate(CYPHEROCK_VENDOR_ID, CYPHEROCK_PRODUCT_ID))

    for d in devices:
        if d.get('path') is not None and d.get('serial_number') is not None:
            d_data: Dict[str, Any] = {}
            d_data['type'] = 'cypherock'
            d_data['model'] = 'cypherock-x1'
            d_data['label'] = None
            d_data['needs_pin_sent'] = False
            d_data['needs_passphrase_sent'] = False
            d_data['path'] = d['path'].decode()
            d_data['fingerprint'] = d['serial_number']  # Using the serial number as the fingerprint for now

            results.append(d_data)

    return results
