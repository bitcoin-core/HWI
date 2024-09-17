# -*- coding: utf-8 -*-
from setuptools import setup

packages = \
['hwilib',
 'hwilib.devices',
 'hwilib.devices.bitbox02_lib',
 'hwilib.devices.bitbox02_lib.bitbox02',
 'hwilib.devices.bitbox02_lib.communication',
 'hwilib.devices.bitbox02_lib.communication.generated',
 'hwilib.devices.bitbox02_lib.communication.u2fhid',
 'hwilib.devices.ckcc',
 'hwilib.devices.jadepy',
 'hwilib.devices.ledger_bitcoin',
 'hwilib.devices.ledger_bitcoin.btchip',
 'hwilib.devices.ledger_bitcoin.exception',
 'hwilib.devices.ledger_bitcoin.ledgercomm',
 'hwilib.devices.ledger_bitcoin.ledgercomm.interfaces',
 'hwilib.devices.trezorlib',
 'hwilib.devices.trezorlib.transport',
 'hwilib.ui']

package_data = \
{'': ['*'], 'hwilib': ['udev/*']}

modules = \
['hwi', 'hwi-qt']
install_requires = \
['cbor2>=5.4.6,<6.0.0',
 'ecdsa>=0,<1',
 'hidapi>=0.14.0',
 'libusb1>=1.7,<4',
 'mnemonic>=0,<1',
 'noiseprotocol>=0.3.1,<0.4.0',
 'protobuf>=4.23.3,<5.0.0',
 'pyaes>=1.6,<2.0',
 'pyserial>=3.5,<4.0',
 'semver>=3.0.1,<4.0.0',
 'typing-extensions>=4.4,<5.0']

extras_require = \
{':python_version >= "3.6" and python_version < "3.7"': ['dataclasses>=0.8,<0.9'],
 'qt:python_version < "3.10"': ['pyside2>=5.14.0,<6.0.0']}

entry_points = \
{'console_scripts': ['hwi = hwilib._cli:main', 'hwi-qt = hwilib._gui:main']}

setup_kwargs = {
    'name': 'hwi',
    'version': '3.1.0',
    'description': 'A library for working with Bitcoin hardware wallets',
    'long_description': "# Bitcoin Hardware Wallet Interface\n\n[![Build Status](https://api.cirrus-ci.com/github/bitcoin-core/HWI.svg)](https://cirrus-ci.com/github/bitcoin-core/HWI)\n[![Documentation Status](https://readthedocs.org/projects/hwi/badge/?version=latest)](https://hwi.readthedocs.io/en/latest/?badge=latest)\n\nThe Bitcoin Hardware Wallet Interface is a Python library and command line tool for interacting with hardware wallets.\nIt provides a standard way for software to work with hardware wallets without needing to implement device specific drivers.\nPython software can use the provided library (`hwilib`). Software in other languages can execute the `hwi` tool.\n\nCaveat emptor: Inclusion of a specific hardware wallet vendor does not imply any endorsement of quality or security.\n\n## Prerequisites\n\nPython 3 is required. The libraries and [udev rules](hwilib/udev/README.md) for each device must also be installed. Some libraries will need to be installed\n\nFor Ubuntu/Debian:\n```\nsudo apt install libusb-1.0-0-dev libudev-dev python3-dev\n```\n\nFor Centos:\n```\nsudo yum -y install python3-devel libusbx-devel systemd-devel\n```\n\nFor macOS:\n```\nbrew install libusb\n```\n\n## Install\n\n```\ngit clone https://github.com/bitcoin-core/HWI.git\ncd HWI\npoetry install # or 'pip3 install .' or 'python3 setup.py install'\n```\n\nThis project uses the [Poetry](https://github.com/sdispater/poetry) dependency manager. HWI and its dependencies can be installed via poetry by executing the following in the root source directory:\n\n```\npoetry install\n```\n\nPip can also be used to automatically install HWI and its dependencies using the `setup.py` file (which is usually in sync with `pyproject.toml`):\n\n```\npip3 install .\n```\n\nThe `setup.py` file can be used to install HWI and its dependencies so long as `setuptools` is also installed:\n\n```\npip3 install -U setuptools\npython3 setup.py install\n```\n\n## Dependencies\n\nSee `pyproject.toml` for all dependencies. Dependencies under `[tool.poetry.dependencies]` are user dependencies, and `[tool.poetry.dev-dependencies]` for development based dependencies. These dependencies will be installed with any of the three above installation methods.\n\n## Usage\n\nTo use, first enumerate all devices and find the one that you want to use with\n\n```\n./hwi.py enumerate\n```\n\nOnce the device type and device path are known, issue commands to it like so:\n\n```\n./hwi.py -t <type> -d <path> <command> <command args>\n```\n\nAll output will be in JSON form and sent to `stdout`.\nAdditional information or prompts will be sent to `stderr` and will not necessarily be in JSON.\nThis additional information is for debugging purposes.\n\nTo see a complete list of available commands and global parameters, run\n`./hwi.py --help`.  To see options specific to a particular command,\npass the `--help` parameter after the command name; for example:\n\n```\n./hwi.py getdescriptors --help\n```\n\n## Documentation\n\nDocumentation for HWI can be found on [readthedocs.io](https://hwi.readthedocs.io/).\n\n### Device Support\n\nFor documentation on devices supported and how they are supported, please check the [device support page](https://hwi.readthedocs.io/en/latest/devices/index.html#support-matrix)\n\n### Using with Bitcoin Core\n\nSee [Using Bitcoin Core with Hardware Wallets](https://hwi.readthedocs.io/en/latest/examples/bitcoin-core-usage.html).\n\n## License\n\nThis project is available under the MIT License, Copyright Andrew Chow.\n",
    'author': 'Ava Chow',
    'author_email': 'me@achow101.com',
    'maintainer': 'None',
    'maintainer_email': 'None',
    'url': 'https://github.com/bitcoin-core/HWI',
    'packages': packages,
    'package_data': package_data,
    'py_modules': modules,
    'install_requires': install_requires,
    'extras_require': extras_require,
    'entry_points': entry_points,
    'python_requires': '>=3.8,<3.13',
}


setup(**setup_kwargs)
