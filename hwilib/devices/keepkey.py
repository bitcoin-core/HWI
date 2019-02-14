# KeepKey interaction script

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
        try:
            client = KeepkeyClient(d_data['path'], password)
            client.client.init_device()
            if not 'keepkey' in client.client.features.vendor:
                continue
            if client.client.features.initialized:
                master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
                d_data['fingerprint'] = get_xpub_fingerprint_hex(master_xpub)
            else:
                d_data['error'] = 'Not initialized'
        except Exception as e:
            d_data['error'] = "Could not open client or get fingerprint information: " + str(e)

        if client:
            client.close()

        results.append(d_data)
    return results
