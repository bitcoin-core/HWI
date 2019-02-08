# Python Trezor Library

This is a stripped down version of the official [python-trezor](https://github.com/trezor/python-trezor) library.

This stripped down version was made at commit [d5c2636f0d1b7da3cb94a4eff6169d77f58cefc1](https://github.com/trezor/python-trezor/tree/d5c2636f0d1b7da3cb94a4eff6169d77f58cefc1).

## Changes

- Removed altcoin support
- Include the compiled protobuf definitions instead of making them on install
- Removed functions that HWI does not use or plan to use
- Changed `TrezorClient` from calling `init_device()` (HWI needs this behavior and doing it in the library makes this simpler)
- Add Keepkey support. Some fields of some messages had to be removed to support both the Keepkey and the Trezor in the same library
