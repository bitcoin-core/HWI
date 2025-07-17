# Python BitBox02 Library

This is a slightly modified version of the official [bitbox02](https://github.com/BitBoxSwiss/bitbox02-firmware/tree/master/py/bitbox02) library.

This was made at tag [py-bitbox02-7.0,0](https://github.com/BitBoxSwiss/bitbox02-firmware/tree/py-bitbox02-7.0.0)

## Changes

- Use our own _base58 rather than external base58 library
- Use relative imports between bitbox02 and communication instead of standard imports that require module installation

See commit 753a9d0c6eec9d7446793a4ce2330fb975d58684 for the modifications made
