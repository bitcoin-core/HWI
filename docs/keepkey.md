# KeepKey

The KeepKey is partially supported by HWI

Current implemented commands are:

* `getmasterxpub`
* `getxpub`
- `setup`
- `wipe`
- `restore`
- `backup`
- `signtx`
- `displayaddress`
- `signmessage`

## `signtx` Caveats

Due to the limitations of the KeepKey, some transactions cannot be signed by a KeepKey.

- Multisig inputs are limited to at most n-of-15 multisigs. This is a firmware limitation.
* Transactions with arbitrary input scripts (scriptPubKey, redeemScript, or witnessScript) and arbitrary output scripts cannot be signed. This is a firmware limitation.

## Note on `backup`

Once the device is backed up at setup, the seed words will not be shown again to be backed up. The implementation here lets users know that `backup` does not work.
