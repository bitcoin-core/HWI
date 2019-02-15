#! /usr/bin/env python3

# Hardware wallet interaction script

import glob
import importlib

from .serializations import PSBT, Base64ToHex, HexToBase64, hash160
from .base58 import get_xpub_fingerprint_as_id, get_xpub_fingerprint_hex, xpub_to_pub_hex
from os.path import dirname, basename, isfile
from .errors import NoPasswordError, UnavailableActionError, DeviceAlreadyInitError, DeviceAlreadyUnlockedError, UnknownDeviceError, BAD_ARGUMENT, NOT_IMPLEMENTED
from .descriptor import Descriptor
import base64

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
                client.fingerprint = master_fpr
                return client
        except:
            if client:
                client.close()
            pass # Ignore things we wouldn't get fingerprints for
    return None

def getmasterxpub(client):
    return client.get_master_xpub()

def signtx(client, psbt):
    # Deserialize the transaction
    tx = PSBT()
    tx.deserialize(psbt)
    return client.sign_tx(tx)

def getxpub(client, path):
    return client.get_pubkey_at_path(path)

def signmessage(client, message, path):
    return client.sign_message(message, path)

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

def displayaddress(client, path=None, desc=None, sh_wpkh=False, wpkh=False):
    if path is not None:
        if sh_wpkh == True and wpkh == True:
            return {'error':'Both `--wpkh` and `--sh_wpkh` can not be selected at the same time.','code':BAD_ARGUMENT}
        return client.display_address(path, sh_wpkh, wpkh)
    elif desc is not None:
        if sh_wpkh == True or wpkh == True:
            return {'error':' `--wpkh` and `--sh_wpkh` can not be combined with --desc','code':BAD_ARGUMENT}
        descriptor = Descriptor.parse(desc, client.is_testnet)
        if descriptor is None:
            return {'error':'Unable to parse descriptor: ' + desc,'code':BAD_ARGUMENT}
        if descriptor.m_path is None:
            return {'error':'Descriptor missing origin info: ' + desc,'code':BAD_ARGUMENT}
        if descriptor.origin_fingerprint != client.fingerprint:
            return {'error':'Descriptor fingerprint does not match device: ' + desc,'code':BAD_ARGUMENT}
        xpub = client.get_pubkey_at_path(descriptor.m_path_base)['xpub']
        if descriptor.base_key != xpub and descriptor.base_key != xpub_to_pub_hex(xpub):
            return {'error':'Key in descriptor does not match device: ' + desc,'code':BAD_ARGUMENT}
        return client.display_address(descriptor.m_path, descriptor.sh_wpkh, descriptor.wpkh)

def setup_device(client, label='', backup_passphrase=''):
    return client.setup_device(label, backup_passphrase)

def wipe_device(client):
    return client.wipe_device()

def restore_device(client, label):
    return client.restore_device(label)

def backup_device(client, label='', backup_passphrase=''):
    return client.backup_device(label, backup_passphrase)

def prompt_pin(client):
    return client.prompt_pin()

def send_pin(client, pin):
    return client.send_pin(pin)

def read_psbt(filename):
    try:
        with open(filename, 'rb') as f:
            return {'psbt':base64.b64encode(f.read()).decode("utf-8")}
    except FileNotFoundError:
        return {'error':'File not found', 'code':BAD_ARGUMENT}
    except Exception:
        return {'error':'Unable to read PSBT from file', 'code':UNKNOWN_ERROR}

def write_psbt(psbt, filename):
    try:
        with open(filename, 'wb') as f:
            f.write(base64.b64decode(psbt))
    except Exception:
        return {'error':'Could not write PSBT to file', 'code':UNKNOWN_ERROR}
    return {'filename':filename}
