# -*- coding: utf-8 -*-
from distutils.core import setup
from os.path import dirname, join
from os import open

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

setup(
    name='hwi',
    version='1.0.1',
    description='A library for working with Bitcoin hardware wallets',
    long_description=open(join(dirname(__file__), 'README.md')).read(),
    author='Andrew Chow',
    author_email='andrew@achow101.com',
    url='https://github.com/bitcoin-core/HWI',
    packages=packages,
    package_data=package_data,
    py_modules=modules,
    install_requires=install_requires,
    extras_require=extras_require,
    entry_points=entry_points,
    python_requires='>=3.5.6',
)
