# Bitcoin Hardware Wallet Interaction scripts

[![Build Status](https://travis-ci.org/achow101/HWI.svg?branch=master)](https://travis-ci.org/achow101/HWI)

This project contains several scripts for interacting with Bitcoin hardware wallets.

## Prerequisites

Python 3 is required. The libraries and udev rules for each device must also be installed.

Install all of the libraries using `pip` (in virtualenv or system):

```
pip3 install hidapi # HID API needed in general
pip3 install trezor[hidapi] # Trezor One
pip3 install btchip-python # Ledger Nano S
pip3 install ecdsa # Needed for btchip-python but is not installed by it
pip3 install git+git://github.com/keepkey/python-keepkey.git@75b32ac2e16c8dbfb5226fa0032e38ea7baafc46#egg=keepkey # KeepKey. The tags and pypi don't have the right version yet, so lock to a specific commit from their git repo
pip3 install ckcc-protocol[cli] # Coldcard
pip3 install pyaes # For digitalbitbox
```
## Install

```
git clone https://github.com/achow101/HWI.git
cd HWI
```

## Usage

To use, first enumerate all devices and find the one that you want to use with

```
./hwi.py enumerate
```

Once the device type and device path is known, issue commands to it like so:

```
./hwi.py -t <type> -d <path> <command> <command args>
```

## Device Support

The below table lists what devices and features are supported for each device.

Please also see [docs](docs/) for additional information about each device.

| Feature \ Device | Ledger Nano S | Trezor One | Digital BitBox | KeepKey | Coldcard |
|:---:|:---:|:---:|:---:|:---:|:---:|
| Support Planned | Yes | Yes | Yes | Yes | Yes |
| Implemented | Yes | Yes | Yes | Partial | Yes |
| xpub retrieval | Yes | Yes | Yes | Yes | Yes |
| Message Signing | Yes | Yes | Yes | No | Yes |
| Device Setup | N/A | Yes | Yes | Yes | N/A |
| Device Wipe | N/A | Yes | Yes | Yes | N/A |
| Device Recovery | N/A | Yes | N/A | Yes | N/A |
| Device Backup | N/A | N/A | Yes | N/A | Yes |
| P2PKH Inputs | Yes | Yes | Yes | Partial | Yes |
| P2SH-P2WPKH Inputs | Yes | Yes | Yes | Partial | Yes |
| P2WPKH Inputs | Yes | Yes | Yes | Partial | Yes |
| P2SH Multisig Inputs | Yes | Yes | Yes | No | N/A |
| P2SH-P2WSH Multisig Inputs | Yes | No | Yes | No | N/A |
| P2WSH Multisig Inputs | Yes | Yes | Yes | No | N/A |
| Bare Multisig Inputs | Yes | N/A | Yes | No | N/A |
| Aribtrary scriptPubKey Inputs | Yes | N/A | Yes | No | N/A |
| Aribtrary redeemScript Inputs | Yes | N/A | Yes | No | N/A |
| Arbitrary witnessScript Inputs | Yes | N/A | Yes | No | N/A |
| Non-wallet inputs | Yes | Yes | Yes | Yes | Yes |
| Mixed Segwit and Non-Segwit Inputs | No | Yes | Yes | Partial | Yes |
| Display on device screen | Yes | Yes | N/A | No | Yes |

## Using with Bitcoin Core

See [Using Bitcoin Core with Hardware Wallets](docs/bitcoin-core-usage.md).

## License

This project is available under the MIT License, Copyright Andrew Chow.
