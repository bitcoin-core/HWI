# BitBox02

The BitBox02 is supported by HWI.

Current implemented commands are:

* `signtx`
* `getxpub`
* `displayaddress`
* `setup`
* `wipe`
* `restore`
* `backup`
* `togglepassphrase`

Multisig (P2WSH only) is supported by the BitBox02, but is not ingerated into HWI yet. Coming
soon^{tm}.

# Usage Notes

## Strict keypaths

The BitBox02 has strict keypath validation.

The only accepted keypaths for xpubs are:

- `m/49'/0'/<account'>` for `p2wpkh-p2sh` (segwit wrapped in P2SH)
- `m/84'/0'/<account'>` for `p2wpkh` (native segwit v0)
- `m/48'/0'/<account'>/2` for p2wsh multisig (native segwit v0 multisig).

`account'` can be between `0'` and `99'`.

For address keypaths, append `/0/<address index>` for a receive and `/1/<change index>` for a change
address. Up to `10000` addresses are supported.

In `--testnet` mode, the second element must be `1'` (e.g. `m/49'/1'/...`).

## Signing with mixed input types

The BitBox02 allows mixing inputs of different script types (e.g. and `p2wpkh-p2sh` `p2wpkh`), as
long as the keypaths use the appropriate bip44 purpose field per input (e.g. `49'` and `84'`) and
all account indexes are the same.

Multisig and singlesig inputs cannot be mixed.

## getmasterxpub and legacy addresses not supported

`getmasterxpub` is the same as `getxpub` at the legacy keypath `m/44'/0'/0'`. Legacy xpub, addresses
and inputs are not supported.
