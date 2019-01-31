#! /usr/bin/env python3

# Hardware wallet interaction script

import glob
import importlib

from .serializations import PSBT, Base64ToHex, HexToBase64, hash160
from .base58 import xpub_to_address, xpub_to_pub_hex, get_xpub_fingerprint_as_id, get_xpub_fingerprint_hex
from os.path import dirname, basename, isfile
from .hwwclient import NoPasswordError, UnavailableActionError, DeviceAlreadyInitError, DeviceAlreadyUnlockedError

# Error codes
NO_DEVICE_PATH = -1
NO_DEVICE_TYPE = -2
DEVICE_CONN_ERROR = -3
UNKNWON_DEVICE_TYPE = -4
INVALID_TX = -5
NO_PASSWORD = -6
BAD_ARGUMENT = -7
NOT_IMPLEMENTED = -8
UNAVAILABLE_ACTION = -9
DEVICE_ALREADY_INIT = -10
DEVICE_ALREADY_UNLOCKED = -11

class UnknownDeviceError(Exception):
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

# Get the client for the device
def get_client(device_type, device_path, password=''):
    class_name = device_type.capitalize()
    module = device_type.lower()

    client = None
    try:
        imported_dev = importlib.import_module('.devices.' + module, __package__)
        client_constructor = getattr(imported_dev, class_name + 'Client')
        client = client_constructor(device_path, password)
    except ImportError as e:
        if client:
            client.close()
        raise UnknownDeviceError('Unknown device type specified')

    return client

# Get a list of all available hardware wallets
def enumerate(password=''):
    result = []

    # Gets the module names of all the files in devices/
    files = glob.glob(dirname(__file__)+"/devices/*.py")
    modules = [ basename(f)[:-3] for f in files if isfile(f) and not f.endswith('__init__.py')]

    for module in modules:
        try:
            imported_dev = importlib.import_module('.devices.' + module, __package__)
            result.extend(imported_dev.enumerate(password))
        except ImportError as e:
            pass # Ignore ImportErrors, the user may not have all device dependencies installed
    return result

# Fingerprint or device type required
def find_device(device_path, password='', device_type=None, fingerprint=None):
    devices = enumerate(password)
    for d in devices:
        if device_type is not None and d['type'] != device_type:
            continue
        client = None
        try:
            client = get_client(d['type'], d['path'], password)
            master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
            master_fpr = get_xpub_fingerprint_hex(master_xpub)
            if fingerprint and master_fpr != fingerprint:
                client.close()
                continue
            else:
                return client
        except:
            if client:
                client.close()
            pass # Ignore things we wouldn't get fingerprints for
    return None

def getmasterxpub(client):
    try:
        return client.get_master_xpub()
    except NotImplementedError as e:
        return {'error': str(e), 'code': NOT_IMPLEMENTED}

def signtx(client, psbt):
    # Deserialize the transaction
    try:
        tx = PSBT()
        tx.deserialize(psbt)
        return client.sign_tx(tx)
    except NotImplementedError as e:
        return {'error': str(e), 'code': NOT_IMPLEMENTED}
    except IOError as e:
        return {'error':'You must provide a PSBT','code':INVALID_TX}
    except Exception as e:
        return {'error': str(e), 'code': BAD_ARGUMENT}

def getxpub(client, path):
    try:
        return client.get_pubkey_at_path(path)
    except NotImplementedError as e:
        return {'error': str(e), 'code': NOT_IMPLEMENTED}

def signmessage(client, message, path):
    try:
        return client.sign_message(message, path)
    except NotImplementedError as e:
        return {'error': str(e), 'code': NOT_IMPLEMENTED}
    except ValueError as e:
        return {'error': str(e), 'code': BAD_ARGUMENT}

def getkeypool(client, path, start, end, internal=False, keypool=False, account=0, sh_wpkh=False, wpkh=True):
    if sh_wpkh == True and wpkh == True:
        return {'error':'Both `--wpkh` and `--sh_wpkh` can not be selected at the same time.','code':BAD_ARGUMENT}

    try:
        master_xpub = client.get_pubkey_at_path('m/0h')['xpub']
    except NotImplementedError as e:
        return {'error': str(e), 'code': NOT_IMPLEMENTED}
    master_fpr = get_xpub_fingerprint_as_id(master_xpub)

    if not path:
      # Master key:
      path = "m/"

      # Purpose
      if wpkh == True:
        path += "84'/"
      elif sh_wpkh == True:
        path += "49'/"
      else:
        path += "44'/"

      # Coin type
      if client.is_testnet == True:
        path += "1'/"
      else:
        path += "0'/"

      # Account
      path += str(account) + '\'/'

      # Receive or change
      if internal == True:
        path += "1/*"
      else:
        path += "0/*"
    else:
      if path[0] != "m":
        return {'error':'Path must start with m/','code':BAD_ARGUMENT}
      if path[-1] != "*":
        return {'error':'Path must end with /*','code':BAD_ARGUMENT}

    # Find the last hardened derivation:
    path = path.replace('\'','h')
    path_suffix = ''
    for component in path.split("/")[::-1]:
      if component[-1] == 'h' or component[-1] == 'm':
        break
      path_suffix = '/' + component + path_suffix
    path_base = path.rsplit(path_suffix)[0]

    # Get the key at the base
    base_key = client.get_pubkey_at_path(path_base)['xpub']

    import_data = []
    this_import = {}

    descriptor_open = 'pkh('
    descriptor_close = ')'
    if wpkh == True:
          descriptor_open = 'wpkh('
    elif sh_wpkh == True:
          descriptor_open = 'sh(wpkh('
          descriptor_close = '))'

    this_import['desc'] = descriptor_open + '[' + master_fpr + path_base.replace('m', '') + ']' + base_key + path_suffix + descriptor_close
    this_import['range'] = {'start': start, 'end': end}
    this_import['timestamp'] = 'now'
    this_import['internal'] = internal
    this_import['keypool'] = keypool
    this_import['watchonly'] = True
    import_data.append(this_import)
    return import_data

def displayaddress(client, path, sh_wpkh=False, wpkh=False):
    if sh_wpkh == True and wpkh == True:
        return {'error':'Both `--wpkh` and `--sh_wpkh` can not be selected at the same time.','code':BAD_ARGUMENT}
    return client.display_address(path, sh_wpkh, wpkh)

def setup_device(client, label='', backup_passphrase=''):
    try:
        return client.setup_device(label, backup_passphrase)
    except UnavailableActionError as e:
        return {'error': str(e), 'code': UNAVAILABLE_ACTION}
    except DeviceAlreadyInitError as e:
        return {'error': str(e), 'code': DEVICE_ALREADY_INIT}
    except ValueError as e:
        return {'error': str(e), 'code': BAD_ARGUMENT}

def wipe_device(client):
    try:
        return client.wipe_device()
    except UnavailableActionError as e:
        return {'error': str(e), 'code': UNAVAILABLE_ACTION}

def restore_device(client, label):
    try:
        return client.restore_device(label)
    except UnavailableActionError as e:
        return {'error': str(e), 'code': UNAVAILABLE_ACTION}
    except DeviceAlreadyInitError as e:
        return {'error': str(e), 'code': DEVICE_ALREADY_INIT}
    except ValueError as e:
        return {'error': str(e), 'code': BAD_ARGUMENT}

def backup_device(client, label='', backup_passphrase=''):
    try:
        return client.backup_device(label, backup_passphrase)
    except UnavailableActionError as e:
        return {'error': str(e), 'code': UNAVAILABLE_ACTION}
    except ValueError as e:
        return {'error': str(e), 'code': BAD_ARGUMENT}

def prompt_pin(client):
    try:
        return client.prompt_pin()
    except DeviceAlreadyUnlockedError as e:
        return {'error': str(e), 'code': DEVICE_ALREADY_UNLOCKED}

def send_pin(client, pin):
    try:
        return client.send_pin(pin)
    except DeviceAlreadyUnlockedError as e:
        return {'error': str(e), 'code': DEVICE_ALREADY_UNLOCKED}
    except ValueError as e:
        return {'error': str(e), 'code': BAD_ARGUMENT}
