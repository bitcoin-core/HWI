# Python BitBox02 Library

This is a slightly modified version of the official [bitbox02](https://github.com/digitalbitbox/bitbox02-firmware/tree/master/py/bitbox02) library.

This was made at commit [5b004e84e2928545db881e380c8ae8782743f5b2](https://github.com/digitalbitbox/bitbox02-firmware/commit/5b004e84e2928545db881e380c8ae8782743f5b2)

## Changes

- Use our own _base58 rather than external base58 library
- Use relative imports between bitbox02 and communication instead of standard imports that require module installation

See commit ac1d5184f1d7c34630b7eb02d1ce5a7b1e16dc61 for the modifications made
