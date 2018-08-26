# Bitcoin Hardware Wallet Interaction scripts

This project contains several scripts for interacting with Bitcoin hardware wallets.

## Prerequisites

Python 3 is required. The libraries and udev rules for each device must also be installed.

Install all of the libraries using `pip` (in virtualenv or system):

```
pip3 install hidapi # HID API needed in general
pip3 install trezor[hidapi] # Trezor One
pip3 install btchip-python # Ledger Nano S
pip3 install keepkey # KeepKey
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

| Feature \ Device | Ledger Nano S | Trezor One | Digital BitBox | KeepKey | ColdCard |
|:---:|:---:|:---:|:---:|:---:|:---:|
| Support Planned | Yes | Yes | Yes | Yes | Yes |
| Implemented | Partial | Partial | Partial | Partial | No |
| xpub retrieval | Yes | Yes | Yes | Yes | No |
| Message Signing | Yes | No | No | No | No |
| Device Setup | No | No | No | No | No |
| Device Recovery | No | No | No | No | No |
| Device Reset | No | No | No | No | No |
| P2PKH Inputs | Yes | Yes | Yes | Partial | No |
| P2SH-P2WPKH Inputs | Yes | Yes | Yes | Partial | No |
| P2WPKH Inputs | Yes | Yes | Yes | Partial | No |
| P2SH Multisig Inputs | Yes | No | Yes | No | No |
| P2SH-P2WSH Multisig Inputs | Yes | No | Yes | No | No |
| P2WSH Multisig Inputs | Yes | No | Yes | No | No |
| Bare Multisig Inputs | Yes | No | Yes | No | No |
| Aribtrary scriptPubKey Inputs | Yes | No | Yes | No | No |
| Aribtrary redeemScript Inputs | Yes | No | Yes | No | No |
| Arbitrary witnessScript Inputs | Yes | No | Yes | No | No |
| Non-wallet inputs | Yes | Yes | Yes | Yes | No |
| Mixed Segwit and Non-Segwit Inputs | No | Yes | Yes | ?? | No |

## License

This project is available under the MIT License, Copyright Andrew Chow.
