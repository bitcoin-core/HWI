# Bitcoin Hardware Wallet Interaction scripts

This project contains several scripts for interacting with Bitcoin hardware wallets.

## Using

You will need Python 3. The main script is `hwi.py`.

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
| P2SH Multisig Inputs | ?? | No | Yes | No | No |
| P2SH-P2WSH Multisig Inputs | ?? | No | Yes | No | No |
| P2WSH Multisig Inputs | ?? | No | Yes | No | No |
| Bare Multisig Inputs | ?? | No | Yes | No | No |
| Aribtrary scriptPubKey Inputs | ?? | No | Yes | No | No |
| Aribtrary redeemScript Inputs | ?? | No | Yes | No | No |
| Arbitrary witnessScript Inputs | ?? | No | Yes | No | No |
| Non-wallet inputs | ?? | Yes | Yes | Yes | No |
| Mixed Segwit and Non-Segwit Inputs | No | Yes | Yes | ?? | No |

## License

This project is available under the MIT License, Copyright Andrew Chow.
