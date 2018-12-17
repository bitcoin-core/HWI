import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="hwi",
    version="0.0.4",
    author="Andrew Chow",
    author_email="andrew@achow101.com",
    description="A library for working with Bitcoin hardware wallets",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/achow101/hwi",
    packages=setuptools.find_packages(exclude=['docs', 'test']),
    install_requires=[
        'hidapi', # HID API needed in general
        'trezor>=0.11.0', # Trezor One
        'btchip-python', # Ledger Nano S
        'keepkey', # KeepKey
        'ckcc-protocol', # Coldcard
        'pyaes',
    ],
    python_requires='>=3',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    extras_require={
        'tests': ['python-bitcoinrpc']
    }
)
