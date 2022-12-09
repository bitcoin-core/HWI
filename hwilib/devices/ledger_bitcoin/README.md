# Ledger Bitcoin application client

This is a stripped down version of the client provided at https://github.com/LedgerHQ/app-bitcoin-new/tree/master/bitcoin_client.

This stripped down version was made at commit [4e82e44ecfe4ba358da9848087e7e597309abc53](https://github.com/LedgerHQ/app-bitcoin-new/commit/4e82e44ecfe4ba358da9848087e7e597309abc53)

## Changes

As the library originally copied several functions and classes from HWI, the majority of changes were to use relative imports to access those things rather than copying them and duplicating code.

* Relative imports to our `common.py`, `key.py`, `_serialize.py`, `psbt.py`, `_script.py`, `base58.py`, `descriptor.py`, and `tx.py`.
* `write_varint` is an alias for `..._serialize.ser_compact_size` rather than a separate function.
* Inline `serialize_str` function into `wallet.py`.
* Inline `bip32_path_from_string` function into `command_builder.py`.
* Inline `ByteStreamparser` class into `client_command.py`.
* Removed `btchip/btchipComm.py` as it is not doing anything.
* Remove usage of `typing.Literal` (needed for Python 3.6 support)
* Removed the `sign_message` function (to be reintroduced when message signing is available for both legacy and new clients).
* Use `ledgercomm` relative import
