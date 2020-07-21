# D'CENT

The D'CENT is partially supported by HWI (firmware version 2.3.0)

Current implemented commands are:

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

Due to the limitations of the D'CENT, some transactions cannot be signed by a D'CENT.

- D'CENT support only p2pkh and p2wpkh inputs
- D'CENT do not support Non-wallet inputs

## Notes on `setup`, `wipe`, `restore`, and `backup`

The D'CENT does not allow you to setup, wipe, restore, or backup it via software. That is done on the device itself. The implementation here is just to let users know those commands do not work.
