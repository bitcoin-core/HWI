# HWI Tests

## Running the tests

This folder contains test cases for HWI. To run these tests, `hwilib` will need to be installed to your python system. You can install it by doing `pip install -e .[tests]` in the root directory.

- `test_bech32.py` tests the bech32 serialization.
This is taken directly from the [python reference implementation](https://github.com/sipa/bech32/blob/master/ref/python/tests.py).
- `test_psbt.py` tests the psbt serialization.
It implements all of the [BIP 174 serialization test vectors](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#Test_Vectors).
- `test_trezor.py` tests the command line interface and the Trezor implementation.
It uses the [Trezor One firmware emulator](https://github.com/trezor/trezor-mcu/#building-for-development).
It also tests usage with `bitcoind`, so the [patched Bitcoin Core](../docs/bitcoin-core-usage.md#bitcoin-core) is required.
- `test_coldcard.py` tests the command line interface and Coldcard implementation.
It uses the [Coldcard simulator](https://github.com/Coldcard/firmware/tree/master/unix#coldcard-desktop-simulator).
It also tests usage with `bitcoind`, so the [patched Bitcoin Core](../docs/bitcoin-core-usage.md#bitcoin-core) is required.

`setup_environment.sh` will build the Trezor emulator, the Coldcard simulator, and the patched `bitcoind`.
if run in the `test/` directory, these will be built in `work/test/trezor-mcu`, `work/test/firmware`, and `work/test/bitcoin` respectively.

`run_tests.py` runs the tests. If run from the `test/` directory, it will be able to find the Trezor emulator, Coldcard simulator, and bitcoind.
Otherwise the paths to those will need to be specified on the command line.
test_trezor.py` and `test_coldcard.py` can be disabled.

If you are building the Trezor emulator, the Coldcard simulator, and `bitcoind` without `setup_environment.sh`, then you will need to make `work/` inside of `test/`.

```
$ cd test
$ mkdir -p work
$ cd work
```

## Trezor emulator

### Dependencies

In order to build the Trezor emulator, the following packages will need to be installed:

```
build-essential curl git python3 python3-pip libsdl2-dev libsdl2-image-dev gcc-arm-none-eabi libnewlib-arm-none-eabi gcc-multilib
```

The python packages can be installed with

```
pip install pipenv
```

### Building

Clone the repository:

```
$ git clone https://github.com/trezor/trezor-mcu/
```

Build the emulator in headless mode:

```
$ cd trezor-mcu
$ export EMULATOR=1 TREZOR_TRANSPORT_V1=1 DEBUG_LINK=1 HEADLESS=1
$ script/setup
$ pipenv install
$ pipenv run script/cibuild
```

## Coldcard simulator

### Dependencies

In order to build the Coldcard simulator, the following packages will need to be installed:

```
build-essential git python3 python3-pip libudev-dev gcc-arm-none-eabi
```

After cloninig the Coldcard repo into this testing folder, the python packages can be installed with:

```
pip install -r ckcc_firmware/requirements.txt
pip install -r ckcc_firmware/unix/requirements.txt
```

### Building

Clone the repository:

```
$ git clone https://github.com/coldcard/firmware
```

Build the emulator in headless mode:

```
$ cd firmware/unix
$ make setup
$ make
```

## Bitbox Simulator

### Dependencies

In order to build the Bitbox simulator, the following packages will need to be installed:

```
build-essential git cmake
```

### Building

Clone the repository:

```
$ git clone https://github.com/achow101/mcu -b simulator
```

Build the simulator:

```
$ cd mcu
$ mkdir -p build && cd build
$ cmake .. -DBUILD_TYPE=simulator
$ make
```

## Bitcoin Core

In order to build `bitcoind`, see [Bitcoin Core's build documentation](https://github.com/bitcoin/bitcoin/blob/master/doc/build-unix.md#linux-distribution-specific-instructions) to get all of the dependencies installed and for instructions on how to build.
