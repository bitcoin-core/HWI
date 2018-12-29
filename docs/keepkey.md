# KeepKey

The KeepKey is partially supported by HWI

Current implemented commands are:

* `getmasterxpub`
* `getxpub`
- `setup`
- `wipe`
- `restore`
- `backup`

## `signtx` Notes

`signtx` has an implementation but has not been tested to be working. Use at your own risk.

## Note on `backup`

Once the device is backed up at setup, the seed words will not be shown again to be backed up. The implementation here lets users know that `backup` does not work.
