# Trezor

The Trezor is partially supported by HWI

Current implemented commands are:

* `getmasterxpub`
* `signtx` (with some caveats)
* `getxpub`

## `signtx` Caveats

Due to the limitations of the Trezor and of the lack of documentation, some transactions cannot be signed by a Trezor.

* The current implementation does not support signing Multisig inputs
* Transactions with arbitrary input scripts (scriptPubKey, redeemScript, or witnessScript) and arbitrary output scripts cannot be signed
