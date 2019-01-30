import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="hwi",
    version="0.0.5",
    author="Andrew Chow",
    author_email="andrew@achow101.com",
    description="A library for working with Bitcoin hardware wallets",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bitcoin-core/hwi",
    packages=setuptools.find_packages(exclude=['docs', 'test']),
    install_requires=[
        'hidapi', # HID API needed in general
        'trezor>=0.11.0', # Trezor One
        'btchip-python', # Ledger Nano S
        'keepkey>=6.0.1', # KeepKey
        'ckcc-protocol[cli]', # Coldcard
        'pyaes',
        'ecdsa', # Needed for Ledger but their library does not install it
    ],
    python_requires='>=3',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    extras_require={
        'tests': ['python-bitcoinrpc']
    },
    entry_points={
        'console_scripts': [
            'hwi = hwilib.cli:main'
        ]
    }
)
