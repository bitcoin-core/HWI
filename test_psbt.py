#! /usr/bin/env python3

from serializations import PSBT, Base64ToHex, HexToBase64
import json
import os

print("Running PSBT Serialization Test")

# Open the data file
with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/test_psbt.json'), encoding='utf-8') as f:
    d = json.load(f)
    invalids = d['invalid']
    valids = d['valid']
    creators = d['creator']
    signers = d['signer']
    combiners = d['combiner']
    finalizers = d['finalizer']
    extractors = d['extractor']

print("Testing invalid PSBTs")
for invalid in invalids:
    try:
        psbt = PSBT()
        psbt.deserialize(Base64ToHex(invalid))
        assert False
    except:
        pass

print("Testing valid PSBTs")
for valid in valids:
    psbt = PSBT()
    psbt.deserialize(Base64ToHex(valid))
    serd = HexToBase64(psbt.serialize()).decode()
    assert(valid == serd)

print("PSBT Serialization tests pass")
