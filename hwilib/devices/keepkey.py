# KeepKey interaction script

from ..errors import HWWError, UNKNOWN_ERROR, common_err_msgs, handle_errors
from .trezorlib.transport import enumerate_devices
from .trezor import TrezorClient
from ..base58 import get_xpub_fingerprint_hex

py_enumerate = enumerate # Need to use the enumerate built-in but there's another function already named that

class KeepkeyClient(TrezorClient):
    def __init__(self, path, password=''):
        super(KeepkeyClient, self).__init__(path, password)
        self.type = 'Keepkey'

def enumerate(password=''):
    results = []
    for dev in enumerate_devices():
        d_data = {}

        d_data['type'] = 'keepkey'
        d_data['path'] = dev.get_path()

        client = None

        with handle_errors(common_err_msgs["enumerate"], d_data):
            client = KeepkeyClient(d_data['path'], password)
            client.client.init_device()
            if not 'keepkey' in client.client.features.vendor:
                continue
            d_data['needs_pin_sent'] = client.client.features.pin_protection and not client.client.features.pin_cached
            d_data['needs_passphrase_sent'] = client.client.features.passphrase_protection and not client.client.features.passphrase_cached
            if d_data['needs_pin_sent']:
                raise DeviceNotReadyError('Keepkey is locked. Unlock by using \'promptpin\' and then \'sendpin\'.')
            if d_data['needs_passphrase_sent'] and not password:
                raise DeviceNotReadyError("Passphrase needs to be specified before the fingerprint information can be retrieved")
            if client.client.features.initialized:
                master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
                d_data['fingerprint'] = get_xpub_fingerprint_hex(master_xpub)
                d_data['needs_passphrase_sent'] = False # Passphrase is always needed for the above to have worked, so it's already sent
            else:
                d_data['error'] = 'Not initialized'

        if client:
            client.close()

        results.append(d_data)
    return results
