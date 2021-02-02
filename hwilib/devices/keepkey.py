# KeepKey interaction script

from ..errors import (
    DEVICE_NOT_INITIALIZED,
    DeviceNotReadyError,
    common_err_msgs,
    handle_errors,
)
from ..hwwclient import (
    DeviceFeature,
    SupportedFeatures,
)
from .trezorlib.transport import (
    enumerate_devices,
    KEEPKEY_VENDOR_IDS,
)
from .trezor import TrezorClient

py_enumerate = enumerate # Need to use the enumerate built-in but there's another function already named that

class KeepkeyClient(TrezorClient):

    # Setup features
    features = SupportedFeatures()
    features.getxpub = DeviceFeature.SUPPORTED
    features.signmessage = DeviceFeature.SUPPORTED
    features.setup = DeviceFeature.SUPPORTED
    features.wipe = DeviceFeature.SUPPORTED
    features.recover = DeviceFeature.SUPPORTED
    features.backup = DeviceFeature.FIRMWARE_NOT_SUPPORTED
    features.sign_p2pkh = DeviceFeature.SUPPORTED
    features.sign_p2sh_p2wpkh = DeviceFeature.SUPPORTED
    features.sign_p2wpkh = DeviceFeature.SUPPORTED
    features.sign_multi_p2sh = DeviceFeature.SUPPORTED
    features.sign_multi_p2sh_p2wsh = DeviceFeature.SUPPORTED
    features.sign_multi_p2wsh = DeviceFeature.SUPPORTED
    features.sign_multi_bare = DeviceFeature.FIRMWARE_NOT_SUPPORTED
    features.sign_arbitrary_bare = DeviceFeature.FIRMWARE_NOT_SUPPORTED
    features.sign_arbitrary_p2sh = DeviceFeature.FIRMWARE_NOT_SUPPORTED
    features.sign_arbitrary_p2sh_p2wsh = DeviceFeature.FIRMWARE_NOT_SUPPORTED
    features.sign_arbitrary_p2wsh = DeviceFeature.FIRMWARE_NOT_SUPPORTED
    features.sign_coinjoin = DeviceFeature.SUPPORTED
    features.sign_mixed_segwit = DeviceFeature.SUPPORTED
    features.display_address = DeviceFeature.SUPPORTED

    def __init__(self, path, password='', expert=False):
        super(KeepkeyClient, self).__init__(path, password, expert)
        self.type = 'Keepkey'

    @classmethod
    def get_features(self):
        return self.features.get_printable_dict()

def enumerate(password=''):
    results = []
    for dev in enumerate_devices():
        # enumerate_devices filters to Trezors and Keepkeys.
        # Only allow Keepkeys and unknowns. Unknown devices will reach the check for vendor later
        if dev.get_usb_vendor_id() not in KEEPKEY_VENDOR_IDS | {-1}:
            continue
        d_data = {}

        d_data['type'] = 'keepkey'
        d_data['model'] = 'keepkey'
        d_data['path'] = dev.get_path()

        client = None

        with handle_errors(common_err_msgs["enumerate"], d_data):
            client = KeepkeyClient(d_data['path'], password)
            client.client.init_device()
            if 'keepkey' not in client.client.features.vendor:
                continue

            if d_data['path'] == 'udp:127.0.0.1:21324':
                d_data['model'] += '_simulator'

            d_data['needs_pin_sent'] = client.client.features.pin_protection and not client.client.features.pin_cached
            d_data['needs_passphrase_sent'] = client.client.features.passphrase_protection # always need the passphrase sent for Keepkey if it has passphrase protection enabled
            if d_data['needs_pin_sent']:
                raise DeviceNotReadyError('Keepkey is locked. Unlock by using \'promptpin\' and then \'sendpin\'.')
            if d_data['needs_passphrase_sent'] and not password:
                raise DeviceNotReadyError("Passphrase needs to be specified before the fingerprint information can be retrieved")
            if client.client.features.initialized:
                d_data['fingerprint'] = client.get_master_fingerprint_hex()
                d_data['needs_passphrase_sent'] = False # Passphrase is always needed for the above to have worked, so it's already sent
            else:
                d_data['error'] = 'Not initialized'
                d_data['code'] = DEVICE_NOT_INITIALIZED

        if client:
            client.close()

        results.append(d_data)
    return results
