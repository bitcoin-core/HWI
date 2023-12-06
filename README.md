# Bitcoin Hardware Wallet Interface

[![Build Status](https://api.cirrus-ci.com/github/bitcoin-core/HWI.svg)](https://cirrus-ci.com/github/bitcoin-core/HWI)
[![Documentation Status](https://readthedocs.org/projects/hwi/badge/?version=latest)](https://hwi.readthedocs.io/en/latest/?badge=latest)

The Bitcoin Hardware Wallet Interface is a Python library and command line tool for interacting with hardware wallets.
It provides a standard way for software to work with hardware wallets without needing to implement device specific drivers.
Python software can use the provided library (`hwilib`). Software in other languages can execute the `hwi` tool.

Caveat emptor: Inclusion of a specific hardware wallet vendor does not imply any endorsement of quality or security.

## Prerequisites

Python 3 is required. The libraries and [udev rules](hwilib/udev/README.md) for each device must also be installed. Some libraries will need to be installed

For Ubuntu/Debian:
```
sudo apt install libusb-1.0-0-dev libudev-dev python3-dev
```

For Centos:
```
sudo yum -y install python3-devel libusbx-devel systemd-devel
```

For macOS:
```
brew install libusb
```

## Install

```
git clone https://github.com/bitcoin-core/HWI.git
cd HWI
poetry install # or 'pip3 install .' or 'python3 setup.py install'
```

This project uses the [Poetry](https://github.com/sdispater/poetry) dependency manager. HWI and its dependencies can be installed via poetry by executing the following in the root source directory:

```
poetry install
```

Pip can also be used to automatically install HWI and its dependencies using the `setup.py` file (which is usually in sync with `pyproject.toml`):

```
pip3 install .
```

The `setup.py` file can be used to install HWI and its dependencies so long as `setuptools` is also installed:

```
pip3 install -U setuptools
python3 setup.py install
```

## Dependencies

See `pyproject.toml` for all dependencies. Dependencies under `[tool.poetry.dependencies]` are user dependencies, and `[tool.poetry.dev-dependencies]` for development based dependencies. These dependencies will be installed with any of the three above installation methods.

## Usage

To use, first enumerate all devices and find the one that you want to use with

```
./hwi.py enumerate
```

Once the device type and device path are known, issue commands to it like so:

```
./hwi.py -t <type> -d <path> <command> <command args>
```

All output will be in JSON form and sent to `stdout`.
Additional information or prompts will be sent to `stderr` and will not necessarily be in JSON.
This additional information is for debugging purposes.

To see a complete list of available commands and global parameters, run
`./hwi.py --help`.  To see options specific to a particular command,
pass the `--help` parameter after the command name; for example:

```
./hwi.py getdescriptors --help
```

## Documentation

Documentation for HWI can be found on [readthedocs.io](https://hwi.readthedocs.io/).

### Device Support

For documentation on devices supported and how they are supported, please check the [device support page](https://hwi.readthedocs.io/en/latest/devices/index.html#support-matrix)

### Using with Bitcoin Core

See [Using Bitcoin Core with Hardware Wallets](https://hwi.readthedocs.io/en/latest/examples/bitcoin-core-usage.html).

## License

This project is available under the MIT License, Copyright Andrew Chow.
