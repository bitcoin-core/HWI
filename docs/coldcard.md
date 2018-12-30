# ColdCard

The ColdCard is partially supported by HWI

Current implemented commands are:

* `getmasterxpub`
* `signtx` (only single key)
* `getxpub`
- `setup`
- `wipe`
- `restore`
- `backup`
- `displayaddress`

## Notes on `setup`, `wipe`, and `restore`

The Coldcard does not allow you to setup, wipe, or restore the device via software. That is done on the device itself. The implementation here is just to let users know those commands do not work.

## Note on `backup`

The `backup` command will create a backup file in the current working directory. This file is protected by the passphrase shown on the Coldcard during the backup process.

## Caveat for `signtx`

The Coldcard firmware only supports signing single key transactions. It cannot sign multisig or arbitrary scripts yet.
