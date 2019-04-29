# Ledger Nano S

The Ledger Nano S is supported by HWI.
Note that the Bitcoin App must be installed and running on the device.

Currently implemented commands:

* `getmasterxpub`
* `signtx` (with some caveats)
* `getxpub`
* `signmessage`
- `displayaddress`
- `setup`
- `wipe`
- `restore`
- `backup`

## `signtx` Caveats

Due to device limitiations, not all kinds of transactions can be signed by a Ledger. 

* Transactions containing both segwit and non-segwit inputs are not entirely supported; only the segwit inputs will be signed in this case.

## Notes on `setup`, `wipe`, `restore`, and `backup`

The Ledger does not allow you to setup, wipe, restore, or backup it via software. That is done on the device itself. The implementation here is just to let users know those commands do not work.
