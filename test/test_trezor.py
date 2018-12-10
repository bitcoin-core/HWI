#! /usr/bin/env python3

import argparse
import atexit
import logging
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time

from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from trezorlib.transport import enumerate_devices
from trezorlib.transport.udp import UdpTransport
from trezorlib.client import TrezorClientDebugLink
from trezorlib import coins

from hwilib.commands import process_commands

parser = argparse.ArgumentParser(description='Test Trezor implementation')
parser.add_argument('emulator', help='Path to the Trezor emulator')
parser.add_argument('bitcoind', help='Path to bitcoind binary')
args = parser.parse_args()

dev_args = ['-t', 'trezor', '-d', 'udp:127.0.0.1:21324']

# Setup logging
logging.basicConfig(format='Trezor Test: %(message)s', level=logging.INFO)

# Start the Trezor emulator
logging.info('Starting Trezor emulator')
emulator_proc = subprocess.Popen([args.emulator])
# Wait for emulator to be up
# From https://github.com/trezor/trezor-mcu/blob/master/script/wait_for_emulator.py
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect(('127.0.0.1', 21324))
sock.settimeout(0)
while True:
    try:
        sock.sendall(b"PINGPING")
        r = sock.recv(8)
        if r == b"PONGPONG":
            break
    except Exception:
        time.sleep(0.05)
# Cleanup
def cleanup_emulator():
    emulator_proc.kill()
atexit.register(cleanup_emulator)

# Setup the emulator
for dev in enumerate_devices():
    # Find the udp transport, that's the emulator
    if isinstance(dev, UdpTransport):
        wirelink = dev
        break
debuglink = wirelink.find_debug()
client = TrezorClientDebugLink(wirelink)
client.set_debuglink(debuglink)
client.set_tx_api(coins.tx_api['Bitcoin'])
client.wipe_device()
client.transport.session_begin()
client.load_device_by_mnemonic(mnemonic='alcohol woman abuse must during monitor noble actual mixed trade anger aisle', pin='', passphrase_protection=False, label='test') # From Trezor device tests

# Tests!

# Test enumerate
logging.info('Testing enumerate')
enum_res = process_commands(['enumerate'])
assert(len(enum_res) == 1)
assert('error' not in enum_res[0])
assert(enum_res[0]['type'] == 'trezor')
assert(enum_res[0]['path'] == 'udp:127.0.0.1:21324')
assert(enum_res[0]['fingerprint'] == '95d8f670')

# Test path + type
logging.info('Testing path and type not specified')
gmxp_res = process_commands(['getmasterxpub'])
assert('error' in gmxp_res)
assert(gmxp_res['error'] == 'You must specify a device type or fingerprint for all commands except enumerate')
assert('code' in gmxp_res)
assert(gmxp_res['code'] == -1)

logging.info('Testing path and type specified')
gmxp_res = process_commands(['-t', enum_res[0]['type'], '-d', enum_res[0]['path'], 'getmasterxpub'])
assert(gmxp_res['xpub'] == 'xpub6D1weXBcFAo8CqBbpP4TbH5sxQH8ZkqC5pDEvJ95rNNBZC9zrKmZP2fXMuve7ZRBe18pWQQsGg68jkq24mZchHwYENd8cCiSb71u3KD4AFH')

# Test fingerprint autodetect
logging.info('Testing fingerprint autodetect')
gmxp_res = process_commands(['-f', enum_res[0]['fingerprint'], 'getmasterxpub'])
assert(gmxp_res['xpub'] == 'xpub6D1weXBcFAo8CqBbpP4TbH5sxQH8ZkqC5pDEvJ95rNNBZC9zrKmZP2fXMuve7ZRBe18pWQQsGg68jkq24mZchHwYENd8cCiSb71u3KD4AFH')

# Test device type autodetect
logging.info('Testing only device type specified')
gmxp_res = process_commands(['-t', enum_res[0]['type'], 'getmasterxpub'])
assert(gmxp_res['xpub'] == 'xpub6D1weXBcFAo8CqBbpP4TbH5sxQH8ZkqC5pDEvJ95rNNBZC9zrKmZP2fXMuve7ZRBe18pWQQsGg68jkq24mZchHwYENd8cCiSb71u3KD4AFH')

# Test getxpub
# BIP 32 test vectors
logging.info('Testing getxpub and getmasterxpub')
with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/bip32_vectors.json'), encoding='utf-8') as f:
    vectors = json.load(f)
for vec in vectors:
    # Setup with xprv
    client.wipe_device()
    client.load_device_by_xprv(xprv=vec['xprv'], pin='', passphrase_protection=False, label='test', language='english')

    # Test getmasterxpub
    gmxp_res = process_commands(dev_args + ['getmasterxpub'])
    assert(gmxp_res['xpub'] == vec['master_xpub'])

    # Test the path derivs
    for path_vec in vec['vectors']:
        gxp_res = process_commands(dev_args + ['getxpub', path_vec['path']])
        assert(gxp_res['xpub'] == path_vec['xpub'])

# signtx and getkeypool need bitcoind, so start that
logging.info('Setting up bitcoind')
datadir = tempfile.mkdtemp()
bitcoind_proc = subprocess.Popen([args.bitcoind, '-regtest', '-datadir=' + datadir, '-noprinttoconsole'])
def cleanup_bitcoind():
    bitcoind_proc.kill()
    shutil.rmtree(datadir)
atexit.register(cleanup_bitcoind)
# Wait for cookie file to be created
while not os.path.exists(datadir + '/regtest/.cookie'):
    time.sleep(0.5)
# Read .cookie file to get user and pass
with open(datadir + '/regtest/.cookie') as f:
    userpass = f.readline().lstrip().rstrip()
rpc = AuthServiceProxy('http://{}@127.0.0.1:18443'.format(userpass))

# Wait for bitcoind to be ready
ready = False
while not ready:
    try:
        rpc.getblockchaininfo()
        ready = True
    except JSONRPCException as e:
        time.sleep(0.5)
        pass

# Setup bitcoind with no privkey wallet and some blocks
rpc.generatetoaddress(101, rpc.getnewaddress())
rpc.createwallet('trezor_test', True)
wrpc = AuthServiceProxy('http://{}@127.0.0.1:18443/wallet/trezor_test'.format(userpass))
wpk_rpc = AuthServiceProxy('http://{}@127.0.0.1:18443/wallet/'.format(userpass))

# Since this is regtest, we need to use regtest in our args
dev_args.append('--testnet')

# Test getkeypool
logging.info('Testing getkeypool: Importable to privkey enabled wallet')
non_keypool_desc = process_commands(dev_args + ['getkeypool', '0', '20'])
import_result = wpk_rpc.importmulti(non_keypool_desc)
assert(import_result[0]['success'])

logging.info('Testing getkeypool: Not importable to privkey enabled wallet')
keypool_desc = process_commands(dev_args + ['getkeypool', '--keypool', '0', '20'])
import_result = wpk_rpc.importmulti(keypool_desc)
assert(import_result[0]['success'] == False)

logging.info('Testing getkeypool: Imports to non privkey enabled wallet keypool')
import_result = wrpc.importmulti(keypool_desc)
assert(import_result[0]['success'])
for i in range(0, 21):
    addr_info = wrpc.getaddressinfo(wrpc.getnewaddress())
    assert(addr_info['hdkeypath'] == "m/44'/1'/0'/0/{}".format(i))

logging.info('Testing getkeypool: Imports to non privkey enabled wallet internal keypool')
keypool_desc = process_commands(dev_args + ['getkeypool', '--keypool', '--internal', '0', '20'])
import_result = wrpc.importmulti(keypool_desc)
assert(import_result[0]['success'])
for i in range(0, 21):
    addr_info = wrpc.getaddressinfo(wrpc.getrawchangeaddress())
    assert(addr_info['hdkeypath'] == "m/44'/1'/0'/1/{}".format(i))

logging.info('Testing getkeypool: --sh_wpkh uses correct derivation path')
keypool_desc = process_commands(dev_args + ['getkeypool', '--keypool', '--sh_wpkh', '0', '20'])
import_result = wrpc.importmulti(keypool_desc)
assert(import_result[0]['success'])
for i in range(0, 21):
    addr_info = wrpc.getaddressinfo(wrpc.getnewaddress())
    assert(addr_info['hdkeypath'] == "m/49'/1'/0'/0/{}".format(i))
keypool_desc = process_commands(dev_args + ['getkeypool', '--keypool', '--sh_wpkh', '--internal', '0', '20'])
import_result = wrpc.importmulti(keypool_desc)
assert(import_result[0]['success'])
for i in range(0, 21):
    addr_info = wrpc.getaddressinfo(wrpc.getrawchangeaddress())
    assert(addr_info['hdkeypath'] == "m/49'/1'/0'/1/{}".format(i))

logging.info('Testing getkeypool: --wpkh uses correct derivation path')
keypool_desc = process_commands(dev_args + ['getkeypool', '--keypool', '--wpkh', '0', '20'])
import_result = wrpc.importmulti(keypool_desc)
assert(import_result[0]['success'])
for i in range(0, 21):
    addr_info = wrpc.getaddressinfo(wrpc.getnewaddress())
    assert(addr_info['hdkeypath'] == "m/84'/1'/0'/0/{}".format(i))
keypool_desc = process_commands(dev_args + ['getkeypool', '--keypool', '--wpkh', '--internal', '0', '20'])
import_result = wrpc.importmulti(keypool_desc)
assert(import_result[0]['success'])
for i in range(0, 21):
    addr_info = wrpc.getaddressinfo(wrpc.getrawchangeaddress())
    assert(addr_info['hdkeypath'] == "m/84'/1'/0'/1/{}".format(i))

logging.info('Testing getkeypool: --account uses correct derivation path')
keypool_desc = process_commands(dev_args + ['getkeypool', '--keypool', '--sh_wpkh', '--account', '3', '0', '20'])
import_result = wrpc.importmulti(keypool_desc)
assert(import_result[0]['success'])
for i in range(0, 21):
    addr_info = wrpc.getaddressinfo(wrpc.getnewaddress())
    assert(addr_info['hdkeypath'] == "m/49'/1'/3'/0/{}".format(i))
keypool_desc = process_commands(dev_args + ['getkeypool', '--keypool', '--sh_wpkh', '--internal', '--account', '3', '0', '20'])
import_result = wrpc.importmulti(keypool_desc)
assert(import_result[0]['success'])
for i in range(0, 21):
    addr_info = wrpc.getaddressinfo(wrpc.getrawchangeaddress())
    assert(addr_info['hdkeypath'] == "m/49'/1'/3'/1/{}".format(i))
keypool_desc = process_commands(dev_args + ['getkeypool', '--keypool', '--wpkh', '--account', '3', '0', '20'])
import_result = wrpc.importmulti(keypool_desc)
assert(import_result[0]['success'])
for i in range(0, 21):
    addr_info = wrpc.getaddressinfo(wrpc.getnewaddress())
    assert(addr_info['hdkeypath'] == "m/84'/1'/3'/0/{}".format(i))
keypool_desc = process_commands(dev_args + ['getkeypool', '--keypool', '--wpkh', '--internal', '--account', '3', '0', '20'])
import_result = wrpc.importmulti(keypool_desc)
assert(import_result[0]['success'])
for i in range(0, 21):
    addr_info = wrpc.getaddressinfo(wrpc.getrawchangeaddress())
    assert(addr_info['hdkeypath'] == "m/84'/1'/3'/1/{}".format(i))

logging.info('Testing getkeypool: --path uses correct derivation path')
keypool_desc = process_commands(dev_args + ['getkeypool', '--keypool', '--path', 'm/0h/0h/4h/*', '0', '20'])
import_result = wrpc.importmulti(keypool_desc)
assert(import_result[0]['success'])
for i in range(0, 21):
    addr_info = wrpc.getaddressinfo(wrpc.getnewaddress())
    assert(addr_info['hdkeypath'] == "m/0'/0'/4'/{}".format(i))

logging.info('Testing getkeypool: check --path parse failures')
keypool_desc = process_commands(dev_args + ['getkeypool', '--keypool', '--path', '/0h/0h/4h/*', '0', '20'])
assert(keypool_desc['error'] == 'Path must start with m/')
assert(keypool_desc['code'] == -7)
keypool_desc = process_commands(dev_args + ['getkeypool', '--keypool', '--path', 'm/0h/0h/4h/', '0', '20'])
assert(keypool_desc['error'] == 'Path must end with /*')
assert(keypool_desc['code'] == -7)

# Test signtx
logging.info('Testing signtx')
# Import some keys to the watch only wallet and send coins to them
keypool_desc = process_commands(dev_args + ['getkeypool', '--keypool', '--sh_wpkh', '30', '40'])
import_result = wrpc.importmulti(keypool_desc)
assert(import_result[0]['success'])
keypool_desc = process_commands(dev_args + ['getkeypool', '--keypool', '--sh_wpkh', '--internal', '30', '40'])
import_result = wrpc.importmulti(keypool_desc)
assert(import_result[0]['success'])
sh_wpkh_addr = wrpc.getnewaddress('', 'p2sh-segwit')
wpkh_addr = wrpc.getnewaddress('', 'bech32')
pkh_addr = wrpc.getnewaddress('', 'legacy')
wrpc.importaddress(wpkh_addr)
wrpc.importaddress(pkh_addr)
wpk_rpc.sendtoaddress(sh_wpkh_addr, 10)
wpk_rpc.sendtoaddress(wpkh_addr, 10)
wpk_rpc.sendtoaddress(pkh_addr, 10)
wpk_rpc.generatetoaddress(6, wpk_rpc.getnewaddress())

# Create a psbt spending the above
psbt = wrpc.walletcreatefundedpsbt([], [{wpk_rpc.getnewaddress():10}], 0, {'includeWatching': True, 'subtractFeeFromOutputs': [0]}, True)
sign_res = process_commands(dev_args + ['signtx', psbt['psbt']])
finalize_res = wrpc.finalizepsbt(sign_res['psbt'])
assert(finalize_res['complete'])
wrpc.sendrawtransaction(finalize_res['hex'])

# Done
logging.info('PASS')
