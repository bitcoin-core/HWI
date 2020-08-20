# Trezor

The Trezor is partially supported by HWI

Current implemented commands are:

* `getmasterxpub`
* `signtx` (with some caveats)
* `getxpub`
- `displayaddress`
- `setup`
- `wipe`
- `restore`
- `backup`
- `togglepassphrase`

## `signtx` Caveats

Due to the limitations of the Trezor, some transactions cannot be signed by a Trezor.

- Multisig inputs are limited to at most n-of-15 multisigs. This is a firmware limitation.
* Transactions with arbitrary input scripts (scriptPubKey, redeemScript, or witnessScript) and arbitrary output scripts cannot be signed. This is a firmware limitation.
* Send-to-self transactions will result in no prompt for outputs as all outputs will be detected as change.

## Note on `backup`

Once the device is backed up at setup, the seed words will not be shown again to be backed up. The implementation here lets users know that `backup` does not work.
