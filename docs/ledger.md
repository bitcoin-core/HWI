# Ledger Nano S

The Ledger Nano S is partially supported by HWI.

Currently implemented commands:

* `getmasterxpub`
* `signtx` (with some caveats)
* `getxpub`
* `signmessage`

## `signtx` Caveats

Due to device limitiations, not all kinds of transactions can be signed by a Ledger. 

* Transactions containing both segwit and non-segwit inputs are not entirely supported; only the segwit inputs will be signed in this case.

## Examples

```
./hwi.py enumerate

[{"type": "ledger", "path": "A very long and complex string representing the path"}, {"type": "ledger", "path": "an other very long string pretty similar"}]
```

To extract the Extended Master Public  

```
 ./hwi.py -t "ledger" -d "A very long and complex string representing the path" getmasterxpub
```

### Useful xpubs

#### BIP44

If you want normal, legacy p2pkh, AKA [pkh][1] addresses (BIP44):

```
 ./hwi.py -t "ledger" -d "A very long and complex string representing the path" getxpub  m/44h/0h/0h
```
To obtain the relevant UTXOs for this xpub from the new Bitcoin Core (0.17):

```
bitcoin-cli scantxoutset start '[{"desc":"pkh(xpubResultingLegacyBIP44/0/*)","range":100},
 {"desc":"pkh(xpubResultingLegacyBIP44/1/*)","range":100}
```
NOTE: use the xpub obtained with the preceding command instead of `xpubResultingLegacyBIP44`.

#### BIP49

If you want the xpub for p2sh-p2wpkh, AKA [sh(wpkh())][1], segwit addresses (BIP49 the only one supported by Ledger Live ATM):

```
 ./hwi.py -t "ledger" -d "A very long and complex string representing the path" getxpub  m/49h/0h/0h

```
To obtain the relevant UTXOs (first 100 addresses) for this xpub from the new Bitcoin Core (0.17):
```
bitcoin-cli scantxoutset start '[{"desc":"sh(wpkh(xpubResultingSegwitBIP49/0/*))","range":100},
 {"desc":"sh(wpkh(xpubResultingLegacyBIP49/1/*))","range":100}
```
NOTE: use the xpub obtained with the preceding command instead of `xpubResultingSegwitBIP49`.

#### BIP84

If you want p2wpkh, bech32, AKA [wpkh()][1], native segwit addresses (BIP84):
```
 ./hwi.py -t "ledger" -d "A very long and complex string representing the path" getxpub  m/84h/0h/0h
```
To obtain the relevant UTXOs (first 100 addresses) for this xpub from the new Bitcoin Core (0.17):
```
bitcoin-cli scantxoutset start '[{"desc":"wpkh(xpubResultingSegwitBIP84/0/*)","range":100},
 {"desc":"wpkh(xpubResultingLegacyBIP84/1/*)","range":100}
```
NOTE: use the xpub obtained with the preceding command instead of `xpubResultingSegwitBIP84`.

[1]: https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
