# Bitcoin Hardware Wallet Interface

[![Build Status](https://travis-ci.org/bitcoin-core/HWI.svg?branch=master)](https://travis-ci.org/bitcoin-core/HWI)

The Bitcoin Hardware Wallet Interface is a Python library and command line tool for interacting with hardware wallets.
It provides a standard way for software to work with hardware wallets without needing to implement device specific drivers.
Python software can use the provided library (`hwilib`). Software in other languages can execute the `hwi` tool.

## Prerequisites

Python 3 is required. The libraries and [udev rules](hwilib/udev/README.md) for each device must also be installed. Some libraries will need to be installed

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

Pip can also be used to install all of the dependencies (in virtualenv or system) required for operation and development. See `pyproject.toml` for all dependencies. Dependencies under `[tool.poetry.dependecies]` are user dependencies, and `[tool.poetry.dev-dependencies]` for development based dependencies.

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

All output will be in JSON form and sent to `stdout`.
Additional information or prompts will be sent to `stderr` and will not necessarily be in JSON.
This additional information is for debugging purposes.

## Device Support

The below table lists what devices and features are supported for each device.

Please also see [docs](docs/) for additional information about each device.

| Feature \ Device | Ledger Nano S | Trezor One | Trezor Model T | Digital BitBox | KeepKey | Coldcard |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Support Planned | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; |
| Implemented | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; |
| xpub retrieval | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; |
| Message Signing | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; |
| Device Setup | N/A | &#9745; | &#9745; | &#9745; | &#9745; | N/A |
| Device Wipe | N/A | &#9745; | &#9745; | &#9745; | &#9745; | N/A |
| Device Recovery | N/A | &#9745; | &#9745; | N/A | &#9745; | N/A |
| Device Backup | N/A | N/A | N/A | &#9745; | N/A | &#9745; |
| P2PKH Inputs | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; |
| P2SH-P2WPKH Inputs | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; |
| P2WPKH Inputs | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; |
| P2SH Multisig Inputs | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; |
| P2SH-P2WSH Multisig Inputs | &#9745; | &#9745; | &#9745; | &#9745; | &#10007; | &#9745; |
| P2WSH Multisig Inputs | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; |
| Bare Multisig Inputs | &#9745; | N/A | N/A | &#9745; | N/A | N/A |
| Arbitrary scriptPubKey Inputs | &#9745; | N/A | N/A | &#9745; | N/A | N/A |
| Arbitrary redeemScript Inputs | &#9745; | N/A | N/A | &#9745; | N/A | N/A |
| Arbitrary witnessScript Inputs | &#9745; | N/A | N/A | &#9745; | N/A | N/A |
| Non-wallet inputs | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; | &#9745; |
| Mixed Segwit and Non-Segwit Inputs | N/A | &#9745; | N/A | &#9745; | &#9745; | &#9745; |
| Display on device screen | &#9745; | &#9745; | &#9745; | N/A | &#9745; | &#9745; |

## Using with Bitcoin Core

See [Using Bitcoin Core with Hardware Wallets](docs/bitcoin-core-usage.md).

## License

This project is available under the MIT License, Copyright Andrew Chow.
