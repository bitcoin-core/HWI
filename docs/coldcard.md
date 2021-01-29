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
- `signmessage`

## Notes on `setup`, `wipe`, and `restore`

The Coldcard does not allow you to setup, wipe, or restore the device via software. That is done on the device itself. The implementation here is just to let users know those commands do not work.

## Note on `backup`

The `backup` command will create a backup file in the current working directory. This file is protected by the passphrase shown on the Coldcard during the backup process.

## Caveat for `signtx`

- The Coldcard firmware only supports signing single key and multisig transactions. It cannot sign arbitrary scripts.
- Multisigs need to be registered on the device before a transaction spending that multisig will be signed by the device.
- Multisigs must use BIP 67. This can be accomplished in Bitcoin Core using the `sortedmulti()` descriptor, available in Bitcoin Core 0.20.
