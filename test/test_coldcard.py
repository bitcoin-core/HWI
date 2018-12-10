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
from hwilib.commands import process_commands
from ckcc.protocol import CCProtocolPacker
from ckcc.client import ColdcardDevice

parser = argparse.ArgumentParser(description='Test Coldcard implementation')
parser.add_argument('simulator', help='Path to the Coldcard simulator')
parser.add_argument('bitcoind', help='Path to bitcoind binary')
args = parser.parse_args()

dev_args = ['-t', 'coldcard', '-d', '/tmp/ckcc-simulator.sock']

# Setup logging
logging.basicConfig(format='Coldcard Test: %(message)s', level=logging.INFO)

# Start the Coldcard simulator
logging.info('Starting Coldcard simulator')
simulator_proc = subprocess.Popen(['python3', os.path.basename(args.simulator)], cwd=os.path.dirname(args.simulator))
# Wait for simulator to be up
while True:
    enum_res = process_commands(['enumerate'])
    if len(enum_res) > 0 and 'error' not in enum_res[0]:
        break
    time.sleep(0.5)
# Cleanup
def cleanup_simulator():
    dev = ColdcardDevice(sn='/tmp/ckcc-simulator.sock')
    resp = dev.send_recv(CCProtocolPacker.logout())
atexit.register(cleanup_simulator)

# Tests!

# Test enumerate
logging.info('Testing enumerate')
enum_res = process_commands(['enumerate'])
assert(len(enum_res) == 1)
assert('error' not in enum_res[0])
assert(enum_res[0]['type'] == 'coldcard')
assert(enum_res[0]['path'] == '/tmp/ckcc-simulator.sock')
assert(enum_res[0]['fingerprint'] == '0f056943')

# Test path + type
logging.info('Testing path and type not specified')
gmxp_res = process_commands(['getmasterxpub'])
assert('error' in gmxp_res)
assert(gmxp_res['error'] == 'You must specify a device type or fingerprint for all commands except enumerate')
assert('code' in gmxp_res)
assert(gmxp_res['code'] == -1)

logging.info('Testing path and type specified')
gmxp_res = process_commands(['-t', enum_res[0]['type'], '-d', enum_res[0]['path'], 'getmasterxpub'])
assert(gmxp_res['xpub'] == 'tpubDDpWvmUrPZrhSPmUzCMBHffvC3HyMAPnWDSAQNBTnj1iZeJa7BZQEttFiP4DS4GCcXQHezdXhn86Hj6LHX5EDstXPWrMaSneRWM8yUf6NFd')

# Test fingerprint autodetect
logging.info('Testing fingerprint autodetect')
gmxp_res = process_commands(['-f', enum_res[0]['fingerprint'], 'getmasterxpub'])
assert(gmxp_res['xpub'] == 'tpubDDpWvmUrPZrhSPmUzCMBHffvC3HyMAPnWDSAQNBTnj1iZeJa7BZQEttFiP4DS4GCcXQHezdXhn86Hj6LHX5EDstXPWrMaSneRWM8yUf6NFd')

# Test device type autodetect
logging.info('Testing only device type specified')
gmxp_res = process_commands(['-t', enum_res[0]['type'], 'getmasterxpub'])
assert(gmxp_res['xpub'] == 'tpubDDpWvmUrPZrhSPmUzCMBHffvC3HyMAPnWDSAQNBTnj1iZeJa7BZQEttFiP4DS4GCcXQHezdXhn86Hj6LHX5EDstXPWrMaSneRWM8yUf6NFd')

# Test getxpub
# BIP 32 test vectors
logging.info('Testing getxpub and getmasterxpub')
with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/coldcard_xpubs.json'), encoding='utf-8') as f:
    vectors = json.load(f)
for vec in vectors:
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
rpc.createwallet('coldcard_test', True)
wrpc = AuthServiceProxy('http://{}@127.0.0.1:18443/wallet/coldcard_test'.format(userpass))
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
# HACK: Skip this in headless simulator because it requires user input
if not args.simulator.endswith('headless.py'):
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
