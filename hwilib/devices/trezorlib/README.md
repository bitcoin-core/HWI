# Python Trezor Library

This is a stripped down version of the official [python-trezor](https://github.com/trezor/trezor-firmware/tree/master/python) library.

This stripped down version was made at commit [345c90ccba1719067859becfd1bcbf1a50d13b35](https://github.com/trezor/trezor-firmware/commit/345c90ccba1719067859becfd1bcbf1a50d13b35).

## Changes

- Removed altcoin support
- Removed functions that HWI does not use or plan to use
- Changed `TrezorClient` from calling `init_device()` (HWI needs this behavior and doing it in the library makes this simpler)
- Add Keepkey support. Some fields of some messages had to be removed to support both the Keepkey and the Trezor in the same library

See commit c175185efcf1b2eb529417eeb5bb701da5c1d3f1 for the modifications made.
