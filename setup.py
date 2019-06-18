# -*- coding: utf-8 -*-
from distutils.core import setup

packages = \
['hwilib',
 'hwilib.devices',
 'hwilib.devices.btchip',
 'hwilib.devices.ckcc',
 'hwilib.devices.trezorlib',
 'hwilib.devices.trezorlib.messages',
 'hwilib.devices.trezorlib.transport']

package_data = \
{'': ['*']}

modules = \
['hwi']
install_requires = \
['ecdsa>=0.13.0,<0.14.0',
 'hidapi>=0.7.99,<0.8.0',
 'libusb1>=1.7,<2.0',
 'mnemonic>=0.18.0,<0.19.0',
 'pyaes>=1.6,<2.0',
 'typing-extensions>=3.7,<4.0']

extras_require = \
{'windist': ['pywin32-ctypes>=0.2.0,<0.3.0']}

entry_points = \
{'console_scripts': ['hwi = hwilib.cli:main']}

setup_kwargs = {
    'name': 'hwi',
    'version': '1.0.1',
    'description': 'A library for working with Bitcoin hardware wallets',
    'long_description': "# Bitcoin Hardware Wallet Interface\n\n[![Build Status](https://travis-ci.org/bitcoin-core/HWI.svg?branch=master)](https://travis-ci.org/bitcoin-core/HWI)\n\nThe Bitcoin Hardware Wallet Interface is a Python library and command line tool for interacting with hardware wallets.\nIt provides a standard way for software to work with hardware wallets without needing to implement device specific drivers.\nPython software can use the provided library (`hwilib`). Software in other languages can execute the `hwi` tool.\n\n## Prerequisites\n\nPython 3 is required. The libraries and udev rules for each device must also be installed. Some libraries will need to be installed\n\nFor Ubuntu/Debian:\n```\nsudo apt install libusb-1.0-0-dev libudev-dev\n```\n\nFor macOS:\n```\nbrew install libusb\n```\n\nThis project uses the [Poetry](https://github.com/sdispater/poetry) dependency manager.\nOnce HWI's source has been downloaded with git clone, it and its dependencies can be installed via poetry by execting the following in the root source directory:\n\n```\npoetry install\n```\n\nPip can also be used to install all of the dependencies (in virtualenv or system):\n\n```\npip3 install hidapi # HID API needed in general\npip3 install ecdsa\npip3 install pyaes\npip3 install typing_extensions\npip3 install mnemonic\npip3 install libusb1\n```\n## Install\n\n```\ngit clone https://github.com/bitcoin-core/HWI.git\ncd HWI\n```\n\n## Usage\n\nTo use, first enumerate all devices and find the one that you want to use with\n\n```\n./hwi.py enumerate\n```\n\nOnce the device type and device path is known, issue commands to it like so:\n\n```\n./hwi.py -t <type> -d <path> <command> <command args>\n```\n\n## Device Support\n\nThe below table lists what devices and features are supported for each device.\n\nPlease also see [docs](docs/) for additional information about each device.\n\n| Feature \\ Device | Ledger Nano S | Trezor One | Trezor Model T | Digital BitBox | KeepKey | Coldcard |\n|:---:|:---:|:---:|:---:|:---:|:---:|:---:|\n| Support Planned | Yes | Yes | Yes | Yes | Yes | Yes |\n| Implemented | Yes | Yes | Yes | Yes | Yes | Yes |\n| xpub retrieval | Yes | Yes | Yes | Yes | Yes | Yes |\n| Message Signing | Yes | Yes | Yes | Yes | Yes | Yes |\n| Device Setup | N/A | Yes | Yes | Yes | Yes | N/A |\n| Device Wipe | N/A | Yes | Yes | Yes | Yes | N/A |\n| Device Recovery | N/A | Yes | Yes | N/A | Yes | N/A |\n| Device Backup | N/A | N/A | N/A | Yes | N/A | Yes |\n| P2PKH Inputs | Yes | Yes | Yes | Yes | Yes | Yes |\n| P2SH-P2WPKH Inputs | Yes | Yes | Yes | Yes | Yes | Yes |\n| P2WPKH Inputs | Yes | Yes | Yes | Yes | Yes | Yes |\n| P2SH Multisig Inputs | Yes | Yes | Yes | Yes | Yes | Yes |\n| P2SH-P2WSH Multisig Inputs | Yes | Yes | Yes | Yes | No | Yes |\n| P2WSH Multisig Inputs | Yes | Yes | Yes | Yes | Yes | Yes |\n| Bare Multisig Inputs | Yes | N/A | N/A | Yes | N/A | N/A |\n| Aribtrary scriptPubKey Inputs | Yes | N/A | N/A | Yes | N/A | N/A |\n| Aribtrary redeemScript Inputs | Yes | N/A | N/A | Yes | N/A | N/A |\n| Arbitrary witnessScript Inputs | Yes | N/A | N/A | Yes | N/A | N/A |\n| Non-wallet inputs | Yes | Yes | Yes | Yes | Yes | Yes |\n| Mixed Segwit and Non-Segwit Inputs | N/A | Yes | N/A | Yes | Yes | Yes |\n| Display on device screen | Yes | Yes | Yes | N/A | Yes | Yes |\n\n## Using with Bitcoin Core\n\nSee [Using Bitcoin Core with Hardware Wallets](docs/bitcoin-core-usage.md).\n\n## License\n\nThis project is available under the MIT License, Copyright Andrew Chow.\n",
    'author': 'Andrew Chow',
    'author_email': 'andrew@achow101.com',
    'url': 'https://github.com/bitcoin-core/HWI',
    'packages': packages,
    'package_data': package_data,
    'py_modules': modules,
    'install_requires': install_requires,
    'extras_require': extras_require,
    'entry_points': entry_points,
    'python_requires': '>=3.5.6',
}


setup(**setup_kwargs)
