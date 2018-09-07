# Ledger Nano S

The Ledger Nano S is partially supported by HWI.

Currently implemented commands:

* `getmasterxpub`
* `signtx` (with some caveats)
* `getxpub`
* `signmessage`

## `signtx` Caveats

Due to device limitiations, not all kinds of transactions can be signed by a Ledger. 

* Transactions containing both segwit and non-segwit inputs are not entirely supported; only the segwit inputs will be signed in this case.
