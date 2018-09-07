# Examples

This Example has been taken with a Ledger nano.

```
./hwi.py enumerate
[{"type": "ledger", "path": "IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/Nano S@14200000/Nano S@0/IOUSBHostHIDDevice@14200000,0", "serial_number": "0001"}, {"type": "ledger", "path": "IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/Nano S@14200000/Nano S@1/IOUSBHostHIDDevice@14200000,1", "serial_number": "0001"}]```
```

To extract the Extended Master Public  

```
 ./hwi.py -t "ledger" -d "IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/Nano S@14200000/Nano S@0/IOUSBHostHIDDevice@14200000,0" getmasterxpub
=> b'e0c4000000'
<= b'1b30010208010003'9000
=> b'f026000000'
<= b''6d00
=> b'e04000000d038000002c8000000080000000'
<= b'4104f4b866b49fb76529a076a1c5b25216c1f4b970cb8e3db9874beb15c5371fdb93747fde522d63be4a564dcda8a71c889f5165eac2990cafee9d416141ae8b09c722313667774c7a76697157783146317a653365676850464d58655438666a57466f4b66f9a82310c4530360ec3fee42049fbb7a3c0bfa72fdf2c5b25b09f1c3df21c938'9000
=> b'e040000009028000002c80000000'
<= b'4104280c846650d7771396a679a55b30c558501f0b5554160c1fbd1d7301c845dacc10c256af2c8d6a13ae4a83763fa747c0d4c09cfa60bfc16714e10b0a938a4a6a2231485451557a6535486571334872553755435174564652745a535839615352674a65d62f97789c088a0b0c3ed57754f75273c6696c0d7812c702ca4f2f72c8631c04'9000
{"xpub": "xpub6CyidiQae2HF71YigFJqteLsRi9D1EvZJm1Lr4DWWxFVruf3vDSbfyxD9znqVkUTUzc4EdgxDRoHXn64gMbFXQGKXg5nPNfvyVcpuPNn92n"}

```

## Useful xpubs

From Bitcoin Core (0.17), it is possible to scan the UTXO set to retrieve the unspent transaction 
outputs relevant for a set of public keys.
It is possible to estract an extended public subkey from our hardware wallet and retrieve from the node 
all the relevant UTXOs, according to a specific [output descriptor][1].

We need to estract from the hardware wallet an Extended Public subKey (xpub) we can derive then 
from without the device and use it as input in Bitcoin Core.

### BIP44

If the hardware wallet is compliant with BIP44 (the default "legacy" in Ledger and Trezor), it has received bitcoins in 
legacy p2pkh, AKA [pkh][1] addresses.
It is necessary to extract the extended public subkey until the last hardened level (m/44h/0h/0h)

```
./hwi.py -t "ledger" -d "IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/Nano S@14200000/Nano S@0/IOUSBHostHIDDevice@14200000,0" getxpub  m/44h/0h/0h
=> b'e0c4000000'
<= b'1b30010208010003'9000
=> b'f026000000'
<= b''6d00
=> b'e04000000d038000002c8000000080000000'
<= b'4104f4b866b49fb76529a076a1c5b25216c1f4b970cb8e3db9874beb15c5371fdb93747fde522d63be4a564dcda8a71c889f5165eac2990cafee9d416141ae8b09c722313667774c7a76697157783146317a653365676850464d58655438666a57466f4b66f9a82310c4530360ec3fee42049fbb7a3c0bfa72fdf2c5b25b09f1c3df21c938'9000
=> b'e040000009028000002c80000000'
<= b'4104280c846650d7771396a679a55b30c558501f0b5554160c1fbd1d7301c845dacc10c256af2c8d6a13ae4a83763fa747c0d4c09cfa60bfc16714e10b0a938a4a6a2231485451557a6535486571334872553755435174564652745a535839615352674a65d62f97789c088a0b0c3ed57754f75273c6696c0d7812c702ca4f2f72c8631c04'9000
{"xpub": "xpub6CyidiQae2HF71YigFJqteLsRi9D1EvZJm1Lr4DWWxFVruf3vDSbfyxD9znqVkUTUzc4EdgxDRoHXn64gMbFXQGKXg5nPNfvyVcpuPNn92n"}

```
and to use the xpub (`xpub6CyidiQae2HF71YigFJqteLsRi9D1EvZJm1Lr4DWWxFVruf3vDSbfyxD9znqVkUTUzc4EdgxDRoHXn64gMbFXQGKXg5nPNfvyVcpuPNn92n`)
in Bitcoin Core (0.17) deriving it further:
* from 0/0 for normal receiving addresses
* from 1/0 for change internal addresses 

```
bitcoin-cli scantxoutset start '[{"desc":"pkh(xpub6CyidiQae2HF71YigFJqteLsRi9D1EvZJm1Lr4DWWxFVruf3vDSbfyxD9znqVkUTUzc4EdgxDRoHXn64gMbFXQGKXg5nPNfvyVcpuPNn92n/0/*)","range":100},
 {"desc":"pkh(xpub6CyidiQae2HF71YigFJqteLsRi9D1EvZJm1Lr4DWWxFVruf3vDSbfyxD9znqVkUTUzc4EdgxDRoHXn64gMbFXQGKXg5nPNfvyVcpuPNn92n/1/*)","range":100}]'
{
  "success": true,
  "searched_items": 49507771,
  "unspents": [
  ],
  "total_amount": 0.00000000
}
```
(there are no UTXOs associated).


### BIP49

If the hardware wallet is compliant with BIP49 (the "Segwit" wallet in Ledger), it has received bitcoins in 
Segwit p2sh-p2wpkh, AKA [sh(wpkh())][1] addresses.
It is necessary to extract the extended public subkey until the last hardened level (m/49h/0h/0h)

```
 ./hwi.py -t "ledger" -d "IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/Nano S@14200000/Nano S@0/IOUSBHostHIDDevice@14200000,0" getxpub  m/49h/0h/0h
=> b'e0c4000000'
<= b'1b30010208010003'9000
=> b'f026000000'
<= b''6d00
=> b'e04000000d03800000318000000080000000'
<= b'410437c2c1ebd83155843b3e8528b43b9786a8dc144df151b27677b76443e54b466d46b0d909d07065a2305cbba41709c78d886be37e446352186a682e9a3f9e2adc22314a594538323869434b7043576368665377396832746857377a533469486e4c444444dcdbabc6f75fbe7609bab04beb88566e3bfc98f66ab030d1af2a070f4064ec'9000
=> b'e040000009028000003180000000'
<= b'4104c34926ea569d26e4ca06ccae25fa4332a07df69fb922a73131cfccf6a544aa3309af253eb5cee3caf8ca9a347a9e8d4429ac55b7a13f72aca36ebb51ca0f489e22314e546e3969454c587046324264664b6f326f316265785a72526e75396d65764663b310aae1803b63157ef3bb7394f985126e5f9ad4b3a6bcb118cd97875dc0e1ce'9000
{"xpub": "xpub6DP8WTA5cy2qWzdtjMUpLJHkzonepEZytzxFLMzkrcW7U4prscYnmXRQ8BesvMP3iqgQUWisAU6ipXnZw2HnNreEPYJW6TUCAfmwJPyYgG6"}
```
and to use the xpub (`xpub6DP8WTA5cy2qWzdtjMUpLJHkzonepEZytzxFLMzkrcW7U4prscYnmXRQ8BesvMP3iqgQUWisAU6ipXnZw2HnNreEPYJW6TUCAfmwJPyYgG6`)
in Bitcoin Core (0.17) deriving it further:
* from 0/0 for normal receiving addresses
* from 1/0 for change internal addresses 

```
bitcoin-cli scantxoutset start '[{"desc":"sh(wpkh(xpub6DP8WTA5cy2qWzdtjMUpLJHkzonepEZytzxFLMzkrcW7U4prscYnmXRQ8BesvMP3iqgQUWisAU6ipXnZw2HnNreEPYJW6TUCAfmwJPyYgG6/0/*))","range":100},
 {"desc":"sh(wpkh(xpub6DP8WTA5cy2qWzdtjMUpLJHkzonepEZytzxFLMzkrcW7U4prscYnmXRQ8BesvMP3iqgQUWisAU6ipXnZw2HnNreEPYJW6TUCAfmwJPyYgG6/1/*))","range":100}]'
{
  "success": true,
  "searched_items": 49507771,
  "unspents": [
  ],
  "total_amount": 0.00000000
}
```

### BIP84

If the hardware wallet is compliant with BIP49 (the "Segwit" wallet in Ledger), it has received bitcoins in 
Segwit p2sh-p2wpkh, AKA [wpkh()][1] native segwit addressesaddresses.
It is necessary to extract the extended public subkey until the last hardened level (m/49h/0h/0h)

```
 ./hwi.py -t "ledger" -d "IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/Nano S@14200000/Nano S@0/IOUSBHostHIDDevice@14200000,0" getxpub  m/84h/0h/0h
=> b'e0c4000000'
<= b'1b30010208010003'9000
=> b'f026000000'
<= b''6d00
=> b'e04000000d03800000548000000080000000'
<= b'4104c79ce10d23b84ec27996e02b83964ec1953fb474ba358e70de62a09cee28dd6590f76b105fb2707c74bbefff0b4aea4156364dd813826848e8c3240d286781b722314270736737486455576a483753704535386e6d62654642773367595a554536776b2017f28f680893adfc004f5ec6db3654577c19b463326329b5d1d90de8dc24cf'9000
=> b'e040000009028000005480000000'
<= b'410483472c03c4157d1b0f8ad98c9391dfbfc820e0180d683658ed863609da5f866aafa260048bc42cd97cb997479fd2619c5d160af68a442a80567b41fe3e763fbe22314e5531544d796971575871367278746375424a3433376d4e75736d745a73554769c03458c3a331489e3271a24a76f4ab024e040e7de7b5e88d8ce058d414f565c2'9000
{"xpub": "xpub6DP9afdc7qsz7s7mwAvciAR2dV6vPC3gyiQbqKDzDcPAq3UQChKPimHc3uCYfTTkpoXdwRTFnVTBdFpM9ysbf6KV34uMqkD3zXr6FzkJtcB"}

```
and to use the xpub (`xpub6DP9afdc7qsz7s7mwAvciAR2dV6vPC3gyiQbqKDzDcPAq3UQChKPimHc3uCYfTTkpoXdwRTFnVTBdFpM9ysbf6KV34uMqkD3zXr6FzkJtcB`) 
in Bitcoin Core (0.17) deriving it further:
* from 0/0 for normal receiving addresses
* from 1/0 for change internal addresses 

```
bitcoin-cli scantxoutset start '[{"desc":"wpkh(xpub6DP9afdc7qsz7s7mwAvciAR2dV6vPC3gyiQbqKDzDcPAq3UQChKPimHc3uCYfTTkpoXdwRTFnVTBdFpM9ysbf6KV34uMqkD3zXr6FzkJtcB/0/*)","range":100},
 {"desc":"wpkh(xpub6DP9afdc7qsz7s7mwAvciAR2dV6vPC3gyiQbqKDzDcPAq3UQChKPimHc3uCYfTTkpoXdwRTFnVTBdFpM9ysbf6KV34uMqkD3zXr6FzkJtcB/1/*)","range":100}]'
{
  "success": true,
  "searched_items": 49507771,
  "unspents": [
  ],
  "total_amount": 0.00000000
}

```


[1]: https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md



