Using Bitcoin Core with Hardware Wallets
****************************************

This approach is fairly manual, requires the command line, and Bitcoin Core >=0.21.0.

Note: For this guide, code lines prefixed with ``$`` means that the command is typed in the terminal. Lines without ``$`` are output of the commands.

Disclaimer
==========

We are not liable for any coins that may be lost through this method. The software mentioned may have bugs. Use at your own risk.

Software
--------

Bitcoin Core
^^^^^^^^^^^^

This method of using hardware wallets uses Bitcoin Core as the wallet for monitoring the blockchain. It allows a user to use their own full node instead of relying on an SPV wallet or vendor provided software.

HWI works with Bitcoin Core >=0.18.0.
However this guide will require Bitcoin Core >=0.21.0 as it uses Descriptor Wallets.

Setup
=====

Clone Bitcoin Core and build it. Clone HWI.

::

    $ git clone https://github.com/bitcoin/bitcoin.git
    $ cd bitcoin
    $ ./autogen.sh
    $ ./configure
    $ make
    $ src/bitcoind -daemon -addresstype=bech32 -changetype=bech32
    $ cd ..
    $ git clone https://github.com/bitcoin-core/HWI.git
    $ cd HWI
    $ python3 setup.py install

You may need some dependencies, on ubuntu install ``libudev-dev`` and ``libusb-1.0-0-dev``

Now we need to find our hardware wallet. We do this using::

    $ ./hwi.py enumerate
    [{"type": "coldcard", "model": "coldcard", "path": "0003:0005:00", "needs_pin_sent": false, "needs_passphrase_sent": false, "fingerprint": "e5dbc9cb"}]

For this example, we will use the Coldcard. As we can see, the device path is ``0003:0005:00``. The fingerprint of the master key is ``e5dbc9cb``. Now that we have the device, we can issue commands to it. So now we want to get some keys and import them into Core.
We will be fetching keys at the BIP 84 default. If ``--path`` and ``--internal`` are not
specified, both receiving and change address descriptors are generated.

::

    $ ./hwi.py -f e5dbc9cb getkeypool 0 1000
    [{"desc": "wpkh([e5dbc9cb/84'/0'/0']xpub6CbtS57jivMSuzcvp5YZxp6JhUU8YWup2axi2xkQRVHY8w4otp8YkEvfWBHgE5rA2AJYNHquuRoLFFdWeSi1UgVohcUeM7SkE9c8NftRwRJ/0/*)#cwyap6p3", "range": [0, 1000], "timestamp": "now", "internal": false, "keypool": true, "active": true, "watchonly": true}, {"desc": "wpkh([e5dbc9cb/84'/0'/0']xpub6CbtS57jivMSuzcvp5YZxp6JhUU8YWup2axi2xkQRVHY8w4otp8YkEvfWBHgE5rA2AJYNHquuRoLFFdWeSi1UgVohcUeM7SkE9c8NftRwRJ/1/*)#f6puu03f", "range": [0, 1000], "timestamp": "now", "internal": true, "keypool": true, "active": true, "watchonly": true}]

We now create a new Bitcoin Core Descriptor Wallet and import the keys into Bitcoin Core. The output is formatted properly for Bitcoin Core so it can be copy and pasted.

::

    $ ../bitcoin/src/bitcoin-cli -named createwallet wallet_name=hwicoldcard disable_private_keys=true descriptors=true
    {
      "name": "hwicoldcard",
      "warning": "Wallet is an experimental descriptor wallet"
    }
    $ ../bitcoin/src/bitcoin-cli -rpcwallet=hwicoldcard importdescriptors '[{"desc": "wpkh([e5dbc9cb/84\'/0\'/0\']xpub6CbtS57jivMSuzcvp5YZxp6JhUU8YWup2axi2xkQRVHY8w4otp8YkEvfWBHgE5rA2AJYNHquuRoLFFdWeSi1UgVohcUeM7SkE9c8NftRwRJ/0/*)#cwyap6p3", "range": [0, 1000], "timestamp": "now", "internal": false, "keypool": true, "active": true, "watchonly": true}, {"desc": "wpkh([e5dbc9cb/84\'/0\'/0\']xpub6CbtS57jivMSuzcvp5YZxp6JhUU8YWup2axi2xkQRVHY8w4otp8YkEvfWBHgE5rA2AJYNHquuRoLFFdWeSi1UgVohcUeM7SkE9c8NftRwRJ/1/*)#f6puu03f", "range": [0, 1000], "timestamp": "now", "internal": true, "keypool": true, "active": true, "watchonly": true}]'
    [
      {
        "success": true
      },
      {
        "success": true
      }
    ]

The Bitcoin Core wallet is now setup to watch two thousand keys (1000 normal, 1000 change) from your hardware wallet and you can use it to track your balances and create transactions. The transactions will need to be signed through HWI.

If the wallet was previously used, you will need to rescan the blockchain. You can either do this using the ``rescanblockchain`` command or editing the ``timestamp`` in the ``importdescriptors`` command.
Here are some examples (``<blockheight>`` refers to a block height before the wallet was created).

::

    $ ../bitcoin/src/bitcoin-cli rescanblockchain <blockheight>
    $ ../bitcoin/src/bitcoin-cli rescanblockchain 500000 # Rescan from block 500000

    $ ../bitcoin/src/bitcoin-cli -rpcwallet=hwicoldcard importdescriptors '[{"desc": "wpkh([e5dbc9cb/84\'/0\'/0\']xpub6CbtS57jivMSuzcvp5YZxp6JhUU8YWup2axi2xkQRVHY8w4otp8YkEvfWBHgE5rA2AJYNHquuRoLFFdWeSi1UgVohcUeM7SkE9c8NftRwRJ/0/*)#cwyap6p3", "range": [0, 1000], "timestamp": <blockheight>, "internal": false, "keypool": true, "active": true, "watchonly": true}, {"desc": "wpkh([e5dbc9cb/84\'/0\'/0\']xpub6CbtS57jivMSuzcvp5YZxp6JhUU8YWup2axi2xkQRVHY8w4otp8YkEvfWBHgE5rA2AJYNHquuRoLFFdWeSi1UgVohcUeM7SkE9c8NftRwRJ/1/*)#f6puu03f", "range": [0, 1000], "timestamp": <blockheight>, "internal": true, "keypool": true, "active": true, "watchonly": true}]'
    $ ../bitcoin/src/bitcoin-cli -rpcwallet=hwicoldcard importdescriptors '[{"desc": "wpkh([e5dbc9cb/84\'/0\'/0\']xpub6CbtS57jivMSuzcvp5YZxp6JhUU8YWup2axi2xkQRVHY8w4otp8YkEvfWBHgE5rA2AJYNHquuRoLFFdWeSi1UgVohcUeM7SkE9c8NftRwRJ/0/*)#cwyap6p3", "range": [0, 1000], "timestamp": 500000, "internal": false, "keypool": true, "active": true, "watchonly": true}, {"desc": "wpkh([e5dbc9cb/84\'/0\'/0\']xpub6CbtS57jivMSuzcvp5YZxp6JhUU8YWup2axi2xkQRVHY8w4otp8YkEvfWBHgE5rA2AJYNHquuRoLFFdWeSi1UgVohcUeM7SkE9c8NftRwRJ/1/*)#f6puu03f", "range": [0, 1000], "timestamp": 500000, "internal": true, "keypool": true, "active": true, "watchonly": true}]' # Imports and rescans from block 500000

Usage
=====

Usage of this primarily involves Bitcoin Core. Currently the GUI only supports generating new receive addresses (once all of the keys are imported) so this guide will only cover the command line.

Receiving
---------

From the folder containing ``bitcoin`` and ``HWI``, go into ``bitcoin``. We will be doing most of the commands here.

::

    $ cd bitcoin

To get a new address, use ``getnewaddress`` as you normally would

::

    $ src/bitcoin-cli -rpcwallet=hwicoldcard getnewaddress
    bc1q2xsn08w749d2tfm7qrkvztlxfmq2564sly4dwl

This address belongs to your hardware wallet. You can check this by doing ``getaddressinfo``::

    $ src/bitcoin-cli -rpcwallet=hwicoldcard getaddressinfo bc1q2xsn08w749d2tfm7qrkvztlxfmq2564sly4dwl
    {
      "address": "bc1q2xsn08w749d2tfm7qrkvztlxfmq2564sly4dwl",
      "scriptPubKey": "001451a1379ddea95aa5a77e00ecc12fe64ec0aa6ab0",
      "ismine": true,
      "solvable": true,
      "desc": "wpkh([e5dbc9cb/84'/0'/0'/0/0]0325ccb1f60a3d0640cbc3bfa1cefc34512d50c32d0e7c102b62e18f23ab69fbc5)#je3ch2kg",
      "parent_desc": "wpkh([e5dbc9cb/84'/0'/0']xpub6CbtS57jivMSuzcvp5YZxp6JhUU8YWup2axi2xkQRVHY8w4otp8YkEvfWBHgE5rA2AJYNHquuRoLFFdWeSi1UgVohcUeM7SkE9c8NftRwRJ/0/*)#cwyap6p3",
      "iswatchonly": false,
      "isscript": false,
      "iswitness": true,
      "witness_version": 0,
      "witness_program": "51a1379ddea95aa5a77e00ecc12fe64ec0aa6ab0",
      "pubkey": "0325ccb1f60a3d0640cbc3bfa1cefc34512d50c32d0e7c102b62e18f23ab69fbc5",
      "ischange": false,
      "timestamp": 1614190663,
      "hdkeypath": "m/84'/0'/0'/0/0",
      "hdseedid": "0000000000000000000000000000000000000000",
      "hdmasterfingerprint": "e5dbc9cb",
      "labels": [
        ""
      ]
    }

You can give this out to people as you normally would. When coins are sent to it, you will see them in your Bitcoin Core wallet as watch-only.

Sending
=======

To send Bitcoin, we will use ``walletcreatefundedpsbt``. This will create a Partially Signed Bitcoin Transaction which is funded by inputs from the wallets (i.e. your watching only inputs selected with Bitcoin Core's coin selection algorithm).
This PSBT can be used with HWI to produce a signed PSBT which can then be finalized and broadcast.

For example, suppose I am sending to 1 BTC to bc1q257z5t76hedc36wmmzva05890ny3kxd7xfwrgy. First I create a funded psbt with BIP 32 derivation paths to be included::

    $ src/bitcoin-cli -rpcwallet=hwicoldcard walletcreatefundedpsbt '[]' '[{"bc1q257z5t76hedc36wmmzva05890ny3kxd7xfwrgy":1}]' 0 '{"includeWatching":true}' true
    {
      "psbt": "cHNidP8BAHECAAAAAU8KWkCU7H4MYBiZHmLey6FavV3L3xLfy4tVEZoubx+2AAAAAAD+////AgDh9QUAAAAAFgAUVTwqL9q+W4jp29iZ19DlfMkbGb78eNcXAAAAABYAFLHuX3WRuPs3ypeQOziNw5qFlBH8AAAAAAABAR8AZc0dAAAAABYAFOHBlVRAplXb3rO39IoSBvhnGZEvIgYCIyDxz3Lnuizva+MtdJPOO9TGoldf5RziYDd63BZWA9QYgDjs2VQAAIABAACAAAAAgAAAAAAAAAAAAAAiAgP0HMQ2K693zCXTCudBUzemDhxLmFGETOnAV7vgDz2r9RiAOOzZVAAAgAEAAIAAAACAAQAAAAAAAAAA",
      "fee": 0.00002820,
      "changepos": 1
    }


Now I take the updated psbt and inspect it with ``decodepsbt``::

    $ src/bitcoin-cli decodepsbt cHNidP8BAHECAAAAAU8KWkCU7H4MYBiZHmLey6FavV3L3xLfy4tVEZoubx+2AAAAAAD+////AgDh9QUAAAAAFgAUVTwqL9q+W4jp29iZ19DlfMkbGb78eNcXAAAAABYAFLHuX3WRuPs3ypeQOziNw5qFlBH8AAAAAAABAR8AZc0dAAAAABYAFOHBlVRAplXb3rO39IoSBvhnGZEvIgYCIyDxz3Lnuizva+MtdJPOO9TGoldf5RziYDd63BZWA9QYgDjs2VQAAIABAACAAAAAgAAAAAAAAAAAAAAiAgP0HMQ2K693zCXTCudBUzemDhxLmFGETOnAV7vgDz2r9RiAOOzZVAAAgAEAAIAAAACAAQAAAAAAAAAA
    {
      "tx": {
        "txid": "e51392c82e13bbfe714c73361aff14ac1a1637abf37587a562844ae5a4265adf",
        "hash": "e51392c82e13bbfe714c73361aff14ac1a1637abf37587a562844ae5a4265adf",
        "version": 2,
        "size": 113,
        "vsize": 113,
        "weight": 452,
        "locktime": 0,
        "vin": [
          {
            "txid": "b61f6f2e9a11558bcbdf12dfcb5dbd5aa1cbde621e9918600c7eec94405a0a4f",
            "vout": 0,
            "scriptSig": {
              "asm": "",
              "hex": ""
            },
            "sequence": 4294967294
          }
        ],
        "vout": [
          {
            "value": 1.00000000,
            "n": 0,
            "scriptPubKey": {
              "asm": "0 553c2a2fdabe5b88e9dbd899d7d0e57cc91b19be",
              "hex": "0014553c2a2fdabe5b88e9dbd899d7d0e57cc91b19be",
              "reqSigs": 1,
              "type": "witness_v0_keyhash",
              "addresses": [
                "bc1q257z5t76hedc36wmmzva05890ny3kxd7xfwrgy"
              ]
            }
          },
          {
            "value": 3.99997180,
            "n": 1,
            "scriptPubKey": {
              "asm": "0 b1ee5f7591b8fb37ca97903b388dc39a859411fc",
              "hex": "0014b1ee5f7591b8fb37ca97903b388dc39a859411fc",
              "reqSigs": 1,
              "type": "witness_v0_keyhash",
              "addresses": [
                "bc1qk8h97av3hran0j5hjqan3rwrn2zegy0unusy49"
              ]
            }
          }
        ]
      },
      "unknown": {
      },
      "inputs": [
        {
          "witness_utxo": {
            "amount": 5.00000000,
            "scriptPubKey": {
              "asm": "0 e1c1955440a655dbdeb3b7f48a1206f86719912f",
              "hex": "0014e1c1955440a655dbdeb3b7f48a1206f86719912f",
              "type": "witness_v0_keyhash",
              "address": "bc1qu8qe24zq5e2ahh4nkl6g5ysxlpn3nyf0wyd5k2"
            }
          },
          "bip32_derivs": [
            {
              "pubkey": "022320f1cf72e7ba2cef6be32d7493ce3bd4c6a2575fe51ce260377adc165603d4",
              "master_fingerprint": "8038ecd9",
              "path": "m/84'/1'/0'/0/0"
            }
          ]
        }
      ],
      "outputs": [
        {
        },
        {
          "bip32_derivs": [
            {
              "pubkey": "03f41cc4362baf77cc25d30ae7415337a60e1c4b9851844ce9c057bbe00f3dabf5",
              "master_fingerprint": "8038ecd9",
              "path": "m/84'/1'/0'/1/0"
            }
          ]
        }
      ],
      "fee": 0.00002820
    }

Once the transaction has been inspected and everything looks good, the transaction can now be signed using HWI.

::

    $ cd ../HWI
    $ ./hwi.py -f e5dbc9cb --testnet signtx cHNidP8BAHECAAAAAU8KWkCU7H4MYBiZHmLey6FavV3L3xLfy4tVEZoubx+2AAAAAAD+////AgDh9QUAAAAAFgAUVTwqL9q+W4jp29iZ19DlfMkbGb78eNcXAAAAABYAFLHuX3WRuPs3ypeQOziNw5qFlBH8AAAAAAABAR8AZc0dAAAAABYAFOHBlVRAplXb3rO39IoSBvhnGZEvIgYCIyDxz3Lnuizva+MtdJPOO9TGoldf5RziYDd63BZWA9QYgDjs2VQAAIABAACAAAAAgAAAAAAAAAAAAAAiAgP0HMQ2K693zCXTCudBUzemDhxLmFGETOnAV7vgDz2r9RiAOOzZVAAAgAEAAIAAAACAAQAAAAAAAAAA

Follow the onscreen instructions, check everything, and approve the transaction. The result will look like::

    {"psbt": "cHNidP8BAHECAAAAAU8KWkCU7H4MYBiZHmLey6FavV3L3xLfy4tVEZoubx+2AAAAAAD+////AgDh9QUAAAAAFgAUVTwqL9q+W4jp29iZ19DlfMkbGb78eNcXAAAAABYAFLHuX3WRuPs3ypeQOziNw5qFlBH8AAAAAAABAR8AZc0dAAAAABYAFOHBlVRAplXb3rO39IoSBvhnGZEvIgICIyDxz3Lnuizva+MtdJPOO9TGoldf5RziYDd63BZWA9RIMEUCIQDMECVXsrFK5XbMQn5yVCvm3zWF1kdCgepf3RSqFDDmAAIgQtty07rN4zBWMjd1qVOtkgOHBAlGaO2Se3LkiNsABYcBAQMEAQAAACIGAiMg8c9y57os72vjLXSTzjvUxqJXX+Uc4mA3etwWVgPUGIA47NlUAACAAQAAgAAAAIAAAAAAAAAAAAAAIgID9BzENiuvd8wl0wrnQVM3pg4cS5hRhEzpwFe74A89q/UYgDjs2VQAAIABAACAAAAAgAEAAAAAAAAAAA=="}

We can now take the PSBT, finalize it, and broadcast it with Bitcoin Core

::

    $ cd ../bitcoin
    $ src/bitcoin-cli finalizepsbt cHNidP8BAHECAAAAAU8KWkCU7H4MYBiZHmLey6FavV3L3xLfy4tVEZoubx+2AAAAAAD+////AgDh9QUAAAAAFgAUVTwqL9q+W4jp29iZ19DlfMkbGb78eNcXAAAAABYAFLHuX3WRuPs3ypeQOziNw5qFlBH8AAAAAAABAR8AZc0dAAAAABYAFOHBlVRAplXb3rO39IoSBvhnGZEvIgICIyDxz3Lnuizva+MtdJPOO9TGoldf5RziYDd63BZWA9RIMEUCIQDMECVXsrFK5XbMQn5yVCvm3zWF1kdCgepf3RSqFDDmAAIgQtty07rN4zBWMjd1qVOtkgOHBAlGaO2Se3LkiNsABYcBAQMEAQAAACIGAiMg8c9y57os72vjLXSTzjvUxqJXX+Uc4mA3etwWVgPUGIA47NlUAACAAQAAgAAAAIAAAAAAAAAAAAAAIgID9BzENiuvd8wl0wrnQVM3pg4cS5hRhEzpwFe74A89q/UYgDjs2VQAAIABAACAAAAAgAEAAAAAAAAAAA==
    {
      "hex": "020000000001014f0a5a4094ec7e0c6018991e62decba15abd5dcbdf12dfcb8b55119a2e6f1fb60000000000feffffff0200e1f50500000000160014553c2a2fdabe5b88e9dbd899d7d0e57cc91b19befc78d71700000000160014b1ee5f7591b8fb37ca97903b388dc39a859411fc02483045022100cc102557b2b14ae576cc427e72542be6df3585d6474281ea5fdd14aa1430e600022042db72d3bacde33056323775a953ad92038704094668ed927b72e488db0005870121022320f1cf72e7ba2cef6be32d7493ce3bd4c6a2575fe51ce260377adc165603d400000000",
      "complete": true
    }
    $ src/bitcoin-cli sendrawtransaction 020000000001014f0a5a4094ec7e0c6018991e62decba15abd5dcbdf12dfcb8b55119a2e6f1fb60000000000feffffff0200e1f50500000000160014553c2a2fdabe5b88e9dbd899d7d0e57cc91b19befc78d71700000000160014b1ee5f7591b8fb37ca97903b388dc39a859411fc02483045022100cc102557b2b14ae576cc427e72542be6df3585d6474281ea5fdd14aa1430e600022042db72d3bacde33056323775a953ad92038704094668ed927b72e488db0005870121022320f1cf72e7ba2cef6be32d7493ce3bd4c6a2575fe51ce260377adc165603d400000000
    e51392c82e13bbfe714c73361aff14ac1a1637abf37587a562844ae5a4265adf

Refilling the keypools
----------------------

Descriptor wallets will constantly generate new addresses from the imported descriptors.
It is not necessary to import additional keys or descriptors to refresh the keypool, Bitcoin Core will do so automatically by using the descriptors.

Derivation Path BIP Compliance
==============================

The instructions above use BIP 84 to derive keys used for P2WPKH addresses (bech32 addresses).
HWI follows BIPs 44, 84, and 49. By default, descriptors will be for P2WPKH addresses with keys derived at ``m/84h/0h/0h/0`` for normal receiving keys and ``m/84h/0h/0h/1`` for change keys.
Using the ``--addr-type legacy`` option will result in P2PKH addresses with keys derived at ``m/44h/0h/0h/0`` for normal receiving keys and ``m/44h/0h/0h/1`` for change keys.
Using the ``--addr-type sh_wit`` option will result in P2SH nested P2WPKH addresses with keys derived at ``m/49h/0h/0h/0`` for normal receiving keys and ``m/49h/0h/0h/1`` for change keys.

To actually get the correct address type when using ``getnewaddress`` from Bitcoin Core, you will need to additionally set ``-addresstype=p2sh-segwit`` and ``-changetype=p2sh-segwit``.
This can be set in the command line (as shown in the example) or in your bitcoin.conf file.

Alternative derivation paths can also be chosen using the ``--path`` option and specifying your own derivation path.
