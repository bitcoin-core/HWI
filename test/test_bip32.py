#! /usr/bin/env python3

# Tests in the JSON file are from BIP 32's test vectors.

import hwilib.bip32 as bip32
import hwilib.base58 as base58
import os
import json
import binascii

print("Starting BIP 32 Public Key Derivation test")

# Open the data file
with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/test_bip32.json'), encoding='utf-8') as f:
    d = json.load(f)

for test in d:
    parent_pk, parent_cc = base58.decompose_xpub(test['parent'])
    (child_pk, child_cc) = bip32.CKDpub(parent_pk, parent_cc, test['index'])
    real_child_pk, real_child_cc = base58.decompose_xpub(test['child'])
    assert(child_pk == real_child_pk)
    assert(child_cc == real_child_cc)

print("Test Completed, passed")
