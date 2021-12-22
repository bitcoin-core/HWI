# Python Trezor Library

This is a stripped down version of the official [python-trezor](https://github.com/trezor/trezor-firmware/tree/master/python) library.

This stripped down version was made at commit [3ed92a72bb2f4c923bd826ffc959e2f1660e75cd](https://github.com/trezor/trezor-firmware/commit/3ed92a72bb2f4c923bd826ffc959e2f1660e75cd).

## Changes

- Removed altcoin support
- Removed functions that HWI does not use or plan to use
- Optionally disable firmware version check in `TrezorClient.call`
- Remove `_MessageTypeMeta` init override

See commit 83d17621d9c61636ccfe8cbf026ba2ed180fac86 for the modifications made.
