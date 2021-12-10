# Python Trezor Library

This is a stripped down version of the official [python-trezor](https://github.com/trezor/trezor-firmware/tree/master/python) library.

This stripped down version was made at commit [3ed92a72bb2f4c923bd826ffc959e2f1660e75cd](https://github.com/trezor/trezor-firmware/commit/3ed92a72bb2f4c923bd826ffc959e2f1660e75cd).

## Changes

- Removed altcoin support
- Removed functions that HWI does not use or plan to use
- Changed `TrezorClient` from calling `init_device()` (HWI needs this behavior and doing it in the library makes this simpler)
- Add Keepkey support. Some fields of some messages had to be removed to support both the Keepkey and the Trezor in the same library

See commits 4f480e49ffb772b585aba96ba310687cb8f2f91d and 0de1b627b3e4a7b6d9c85e3b49eea5c2d5b28541 for the modifications made.
