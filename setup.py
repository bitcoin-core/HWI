# -*- coding: utf-8 -*-
from distutils.core import setup

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
    'version': '0.0.5',
    'description': 'A library for working with Bitcoin hardware wallets',
    'long_description': '# Bitcoin Hardware Wallet Interaction scripts\n\n[![Build Status](https://travis-ci.org/bitcoin-core/HWI.svg?branch=master)](https://travis-ci.org/bitcoin-core/HWI)\n\nThis project contains several scripts for interacting with Bitcoin hardware wallets.\n\n## Prerequisites\n\nPython 3 is required. The libraries and udev rules for each device must also be installed.\n\nInstall all of the libraries using `pip` (in virtualenv or system):\n\n```\npip3 install hidapi # HID API needed in general\npip3 install trezor[hidapi] # Trezor One\npip3 install btchip-python # Ledger Nano S\npip3 install ecdsa # Needed for btchip-python but is not installed by it\npip3 install keepkey # KeepKey\npip3 install ckcc-protocol[cli] # Coldcard\npip3 install pyaes # For digitalbitbox\n```\n## Install\n\n```\ngit clone https://github.com/bitcoin-core/HWI.git\ncd HWI\n```\n\n## Usage\n\nTo use, first enumerate all devices and find the one that you want to use with\n\n```\n./hwi.py enumerate\n```\n\nOnce the device type and device path is known, issue commands to it like so:\n\n```\n./hwi.py -t <type> -d <path> <command> <command args>\n```\n\n## Device Support\n\nThe below table lists what devices and features are supported for each device.\n\nPlease also see [docs](docs/) for additional information about each device.\n\n| Feature \\ Device | Ledger Nano S | Trezor One | Digital BitBox | KeepKey | Coldcard |\n|:---:|:---:|:---:|:---:|:---:|:---:|\n| Support Planned | Yes | Yes | Yes | Yes | Yes |\n| Implemented | Yes | Yes | Yes | Yes | Yes |\n| xpub retrieval | Yes | Yes | Yes | Yes | Yes |\n| Message Signing | Yes | Yes | Yes | Yes | Yes |\n| Device Setup | N/A | Yes | Yes | Yes | N/A |\n| Device Wipe | N/A | Yes | Yes | Yes | N/A |\n| Device Recovery | N/A | Yes | N/A | Yes | N/A |\n| Device Backup | N/A | N/A | Yes | N/A | Yes |\n| P2PKH Inputs | Yes | Yes | Yes | Yes | Yes |\n| P2SH-P2WPKH Inputs | Yes | Yes | Yes | Yes | Yes |\n| P2WPKH Inputs | Yes | Yes | Yes | Yes | Yes |\n| P2SH Multisig Inputs | Yes | Yes | Yes | Yes | N/A |\n| P2SH-P2WSH Multisig Inputs | Yes | No | Yes | No | N/A |\n| P2WSH Multisig Inputs | Yes | No | Yes | Yes | N/A |\n| Bare Multisig Inputs | Yes | N/A | Yes | N/A | N/A |\n| Aribtrary scriptPubKey Inputs | Yes | N/A | Yes | N/A | N/A |\n| Aribtrary redeemScript Inputs | Yes | N/A | Yes | N/A | N/A |\n| Arbitrary witnessScript Inputs | Yes | N/A | Yes | N/A | N/A |\n| Non-wallet inputs | Yes | Yes | Yes | Yes | Yes |\n| Mixed Segwit and Non-Segwit Inputs | N/A | Yes | Yes | Yes | Yes |\n| Display on device screen | Yes | Yes | N/A | Yes | Yes |\n\n## Using with Bitcoin Core\n\nSee [Using Bitcoin Core with Hardware Wallets](docs/bitcoin-core-usage.md).\n\n## License\n\nThis project is available under the MIT License, Copyright Andrew Chow.\n',
    'author': 'Andrew Chow',
    'author_email': 'andrew@achow101.com',
    'url': 'https://github.com/bitcoin-core/HWI',
    'py_modules': modules,
    'install_requires': install_requires,
    'extras_require': extras_require,
    'entry_points': entry_points,
    'python_requires': '>=3.5.6',
}


setup(**setup_kwargs)
