# Digital BitBox

The Digital BitBox is partially supported by HWI

Current implemented commands are:

* `getmasterxpub`
* `signtx`
* `getxpub` (with some caveats)

## Usage Notes

You must specify your Digital BitBox password using the `-p` option. E.g.

```
./hwi.py -t digitalbitbox -d 0001:0001:00 -p password getmasterxpub
```

## `getxpub` Caveats

The Digital BitBox requires that one of the levels in the derivation path is hardened.
