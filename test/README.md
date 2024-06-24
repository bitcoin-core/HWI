# HWI Tests

## Running the tests

This folder contains test cases for HWI. To run these tests, `hwilib` will need to be installed to your python system. You can install it by doing `pip install -e .[tests]` in the root directory.

- `test_bech32.py` tests the bech32 serialization.
This is taken directly from the [python reference implementation](https://github.com/sipa/bech32/blob/master/ref/python/tests.py).
- `test_psbt.py` tests the psbt serialization.
It implements all of the [BIP 174 serialization test vectors](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#Test_Vectors).
- `test_trezor.py` tests the command line interface and the Trezor implementation.
It uses the [Trezor One firmware emulator](https://github.com/trezor/trezor-firmware/blob/master/docs/legacy/index.md#local-development-build) and [Trezor Model T firmware emulator](https://github.com/trezor/trezor-firmware/blob/master/docs/core/emulator/index.md).
It also tests usage with `bitcoind`.
- `test_keepkey.py` tests the command line interface and the Keepkey implementation.
It uses the [Keepkey firmware emulator](https://github.com/keepkey/keepkey-firmware/blob/master/docs/Build.md).
It also tests usage with `bitcoind`.
- `test_coldcard.py` tests the command line interface and Coldcard implementation.
It uses the [Coldcard simulator](https://github.com/Coldcard/firmware/tree/master/unix#coldcard-desktop-simulator).
It also tests usage with `bitcoind`.
- `test_jade.py` tests the command line interface and Blockstream Jade implementation.
It uses the [Espressif fork of the Qemu emulator](https://github.com/espressif/qemu.git).
It also tests usage with `bitcoind`.
- `test_bitbox02.py` tests the command line interface and the BitBox02 implementation.
It uses the [BitBox02 simulator](https://github.com/BitBoxSwiss/bitbox02-firmware/tree/master/test/simulator).
It also tests usage with `bitcoind`.

`setup_environment.sh` will build the Trezor emulator, the Coldcard simulator, the Keepkey emulator, the Digital Bitbox simulator, the Jade emulator, the BitBox02 simulator and `bitcoind`.
if run in the `test/` directory, these will be built in `work/test/trezor-firmware`, `work/test/firmware`, `work/test/keepkey-firmware`, `work/test/mcu`, `work/test/bitbox02-firmware` and `work/test/bitcoin` respectively.
In order to build each simulator/emulator, you will need to use command line arguments.
These are `--trezor-1`, `--trezor-t`, `--coldcard`, `--keepkey`, `--bitbox01`, `--jade`, `--bitbox02` and `--bitcoind`.
If an environment variable is not present or not set, then the simulator/emulator or bitcoind that it guards will not be built.

`run_tests.py` runs the tests. If run from the `test/` directory, it will be able to find the Trezor emulator, Coldcard simulator, Keepkey emulator, Digital Bitbox simulator, Jade emulator, BitBox02 simulator and bitcoind.
Otherwise the paths to those will need to be specified on the command line.
`test_trezor.py`, `test_coldcard.py`, `test_keepkey.py`, `test_jade.py`, `test_bitbox02.py` and `test/test_digitalbitbox.py` can be disabled.

If you are building the Trezor emulator, the Coldcard simulator, the Keepkey emulator, the Jade emulator, the Digital Bitbox simulator, and `bitcoind` without `setup_environment.sh`, then you will need to make `work/` inside of `test/`.

```
$ cd test
$ mkdir -p work
$ cd work
```

## Trezor emulator

### Dependencies

In order to build the Trezor emulator, the following packages will need to be installed:

```
build-essential curl git python3 python3-pip libsdl2-dev libsdl2-image-dev gcc-arm-none-eabi libnewlib-arm-none-eabi gcc-multilib protobuf-compiler clang
```

The python packages can be installed with

```
pip install pipenv
```

### Building

Clone the repository:

```
$ git clone https://github.com/trezor/trezor-firmware/
```

Build the emulator in headless mode:

```
$ cd trezor-firmware/legacy
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

After cloning the Coldcard repo into this testing folder, the python packages can be installed with:

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
$ git clone https://github.com/digitalbitbox/mcu
```

Build the simulator:

```
$ cd mcu
$ mkdir -p build && cd build
$ cmake .. -DBUILD_TYPE=simulator
$ make
```

## KeepKey emulator

### Dependencies

In order to build the KeepKey emulator, the following packages will need to be installed:

```
build-essential git python2 python2-pip
```

The python packages can be installed with

```
pip install protobuf
```

### Building

Clone the repository and dependencies:

```
$ git clone https://github.com/keepkey/keepkey-firmware.git
$ cd keepkey-firmware
$ git clone https://github.com/nanopb/nanopb.git -b nanopb-0.2.9.2
```

Build the emulator:

```
$ export PATH=$PATH:`pwd`/nanopb/generator
$ cmake -C cmake/caches/emulator.cmake . -DNANOPB_DIR=nanopb/ -DKK_HAVE_STRLCAT=OFF -DKK_HAVE_STRLCPY=OFF
$ make kkemu
```

## Jade emulator

### Dependencies

In order to build the Jade emulator, the following packages will need to be installed:

```
build-essential git cmake ninja-build libusb-1.0-0 libglib2.0-dev libpixman-1-dev libgcrypt20-dev
```

### Building

Building the jade firmware and emulator can be a bit involved.  See `setup_environment.sh`.

NOTE: the branch and commit of the esp-idf toolchain and the qemu emulator required are best extracted
from the Jade Dockerfile at the Jade commit being built.

Clone the jade repository and extract the branches and commits of the dependencies:

```
$ mkdir jade
$ git clone --recursive --branch master https://github.com/Blockstream/Jade.git ./jade
$ ESP_IDF_BRANCH=$(grep "ARG ESP_IDF_BRANCH=" Dockerfile | cut -d\= -f2)
$ ESP_IDF_COMMIT=$(grep "ARG ESP_IDF_COMMIT=" Dockerfile | cut -d\= -f2)
$ ESP_QEMU_BRANCH=$(grep "ARG ESP_QEMU_BRANCH=" Dockerfile | cut -d\= -f2)
$ ESP_QEMU_COMMIT=$(grep "ARG ESP_QEMU_COMMIT=" Dockerfile | cut -d\= -f2)
```

Clone and build the qemu emulator:
```
$ mkdir qemu
$ git clone --depth 1 --branch ${ESP_QEMU_BRANCH} --single-branch --recursive https://github.com/espressif/qemu.git ./qemu
$ cd qemu && checkout ${ESP_QEMU_COMMIT}
$ ./configure \
    --target-list=xtensa-softmmu \
    --enable-gcrypt \
    --enable-sanitizers \
    --disable-user \
    --disable-opengl \
    --disable-curses \
    --disable-capstone \
    --disable-vnc \
    --disable-parallels \
    --disable-qed \
    --disable-vvfat \
    --disable-vdi \
    --disable-qcow1 \
    --disable-dmg \
    --disable-cloop \
    --disable-bochs \
    --disable-replication \
    --disable-live-block-migration \
    --disable-keyring \
    --disable-containers \
    --disable-docs \
    --disable-libssh \
    --disable-xen \
    --disable-tools \
    --disable-zlib-test \
    --disable-sdl \
    --disable-gtk \
    --disable-vhost-scsi \
    --disable-qom-cast-debug \
    --disable-tpm
$ ninja -C build
$ cd ..
```

Clone and install the relevant version of the esp-idf libraries and toolchain:
```
$ mkdir ./esp && cd ./esp
$ export IDF_TOOLS_PATH="$(pwd)/esp-idf-tools"
$ git clone --quiet --depth=1 --branch ${ESP_IDF_BRANCH} --single-branch --recursive https://github.com/espressif/esp-idf.git
$ cd esp-idf && git checkout ${ESP_IDF_COMMIT}
$ ./install.sh esp32
$ . ./export.sh
$ cd ../..
```
(Note: once the tools are installed, any new shell only needs to source the `./export.sh` file.)

Build the Jade fw configured for the emulator:
```
$ cd jade
$ rm -f sdkconfig
$ cp configs/sdkconfig_qemu.defaults sdkconfig.defaults
$ idf.py all
```

Create an emulator rom image:
```
$ esptool.py --chip esp32 merge_bin --fill-flash-size 4MB -o main/qemu/flash_image.bin \
$ --flash_mode dio --flash_freq 40m --flash_size 4MB \
$ 0x9000 build/partition_table/partition-table.bin \
$ 0xe000 build/ota_data_initial.bin \
$ 0x1000 build/bootloader/bootloader.bin \
$ 0x10000 build/jade.bin
$ cd ..
```

Extract the minimal artifacts required to run the emulator
```
$ rm -fr simulator
$ mkdir simulator
$ cp qemu/build/qemu-system-xtensa simulator/
$ cp -R qemu/pc-bios simulator/
$ cp jade/main/qemu/flash_image.bin simulator/
$ cp jade/main/qemu/qemu_efuse.bin simulator/
$ cd ..
```

## Ledger emulator

### Dependencies

In order to build the Ledger emulator, the following packages will need to be installed:

```
cmake gcc-arm-linux-gnueabihf libc6-dev-armhf-cross gdb-multiarch qemu-user-static
```

The python packages can be installed with

```
pip install construct flask-restful jsonschema mnemonic pyelftools pillow requests
```

### Building

Clone the repository:

```
$ git clone --recursive https://github.com/LedgerHQ/speculos.git
```

Build the emulator:

```
$ cmake -Bbuild -H.
$ make -C build/
```

## Coldcard emulator

Clone the repository:

```
git clone --recursive https://github.com/Coldcard/firmware.git
```

### Dependencies

In order to build the Coldcard emulator, the following packages will need to be installed:

```
build-essential git python3 python3-pip libudev-dev gcc-arm-none-eabi libffi-dev xterm swig libpcsclite-dev
```
You also have to install its python dependencies

```
pip install -r requirements.txt
```

## BitBox02 Simulator

### Dependencies

In order to build the BitBox02 simulator, the following packages will need to be installed:

```
apt install docker.io
```

### Building

Clone the repository:

```
git clone --recursive https://github.com/BitBoxSwiss/bitbox02-firmware.git
```

Pull the BitBox02 firmware Docker image:

```
docker pull shiftcrypto/firmware_v2:latest
```

Build the simulator:

```
cd bitbox02-firmware
make dockerdev
make simulator
```


## Bitcoin Core

In order to build `bitcoind`, see [Bitcoin Core's build documentation](https://github.com/bitcoin/bitcoin/blob/master/doc/build-unix.md#linux-distribution-specific-instructions) to get all of the dependencies installed and for instructions on how to build.
