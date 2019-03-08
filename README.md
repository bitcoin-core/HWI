# Bitcoin Hardware Wallet Interface

[![Build Status](https://travis-ci.org/bitcoin-core/HWI.svg?branch=master)](https://travis-ci.org/bitcoin-core/HWI)

The Bitcoin Hardware Wallet Interface is a Python library and command line tool for interacting with hardware wallets.
It provides a standard way for software to work with hardware wallets without needing to implement device specific drivers.
Python software can use the provided library (`hwilib`). Software in other languages can execute the `hwi` tool.

## Prerequisites

Python 3 is required. The libraries and udev rules for each device must also be installed. Some libraries will need to be installed

For Ubuntu/Debian:
```
sudo apt install libusb-1.0-0-dev libudev-dev
```

For macOS:
```
brew install libusb
```

This project uses the [Poetry](https://github.com/sdispater/poetry) dependency manager.
Once HWI's source has been downloaded with git clone, it and its dependencies can be installed via poetry by execting the following in the root source directory:

```
poetry install
```

Pip can also be used to install all of the dependencies (in virtualenv or system):

```
pip3 install hidapi # HID API needed in general
pip3 install ecdsa
pip3 install pyaes
pip3 install typing_extensions
pip3 install mnemonic
pip3 install libusb1
```
## Install

```
git clone https://github.com/bitcoin-core/HWI.git
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
| Implemented | Yes | Yes | Yes | Yes | Yes |
| xpub retrieval | Yes | Yes | Yes | Yes | Yes |
| Message Signing | Yes | Yes | Yes | Yes | Yes |
| Device Setup | N/A | Yes | Yes | Yes | N/A |
| Device Wipe | N/A | Yes | Yes | Yes | N/A |
| Device Recovery | N/A | Yes | N/A | Yes | N/A |
| Device Backup | N/A | N/A | Yes | N/A | Yes |
| P2PKH Inputs | Yes | Yes | Yes | Yes | Yes |
| P2SH-P2WPKH Inputs | Yes | Yes | Yes | Yes | Yes |
| P2WPKH Inputs | Yes | Yes | Yes | Yes | Yes |
| P2SH Multisig Inputs | Yes | Yes | Yes | Yes | N/A |
| P2SH-P2WSH Multisig Inputs | Yes | No | Yes | No | N/A |
| P2WSH Multisig Inputs | Yes | No | Yes | Yes | N/A |
| Bare Multisig Inputs | Yes | N/A | Yes | N/A | N/A |
| Aribtrary scriptPubKey Inputs | Yes | N/A | Yes | N/A | N/A |
| Aribtrary redeemScript Inputs | Yes | N/A | Yes | N/A | N/A |
| Arbitrary witnessScript Inputs | Yes | N/A | Yes | N/A | N/A |
| Non-wallet inputs | Yes | Yes | Yes | Yes | Yes |
| Mixed Segwit and Non-Segwit Inputs | N/A | Yes | Yes | Yes | Yes |
| Display on device screen | Yes | Yes | N/A | Yes | Yes |

## Using with Bitcoin Core

See [Using Bitcoin Core with Hardware Wallets](docs/bitcoin-core-usage.md).

## License

This project is available under the MIT License, Copyright Andrew Chow.
