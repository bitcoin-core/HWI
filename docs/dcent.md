# D'cent

The D'cent is partially supported by HWI (firmware version 2.3.0)

Current implemented commands are:

* `getmasterxpub`
* `signtx` (with some caveats)
* `getxpub`
* `signmessage`
- `displayaddress`

## `signtx` Caveats

Due to the limitations of the D'cent, some transactions cannot be signed by a D'cent.

- D'cent support only p2pkh and p2wpkh inputs
- D'cent do not support Non-wallet inputs
