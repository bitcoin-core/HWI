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

`backup` is forbidden in HSM mode.

## Caveat for `signtx`

- The Coldcard firmware only supports signing single key and multisig transactions. It cannot sign arbitrary scripts.
- Multsigs need to be registered on the device before a transaction spending that multisig will be signed by the device.
- Multisigs must use BIP 67. This can be accomplished in Bitcoin Core using the `sortedmulti()` descriptor, available in Bitcoin Core 0.20.

## HSM Mode

Coldcard MK3 brings a new feature called "HSM mode", which automatically signs transactions without a manual approval. HSM can be preconfigured with a JSON file to limit signing transactions by custom rules. By default HSM forbids sharing xpubs and addresses. However HWI needs xpubs and addresses to perform `signtx` and other commands. You can override this default settings by:

```json
{
    "share_xpubs": ["any"],
    "share_addrs": ["any"]
}
```

More information can be found: <https://coldcardwallet.com/docs/hsm/rules>