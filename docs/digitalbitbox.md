# Digital BitBox

The Digital BitBox is supported by HWI

Current implemented commands are:

* `getmasterxpub`
* `signtx`
* `getxpub` (with some caveats)
- `setup`
- `wipe`
- `restore`
- `backup`
- `displayaddress`

## Usage Notes

You must specify your Digital BitBox password using the `-p` option. E.g.

```
./hwi.py -t digitalbitbox -d 0001:0001:00 -p password getmasterxpub
```

## `getxpub` Caveats

The Digital BitBox requires that one of the levels in the derivation path is hardened.

## Note on `restore`

The Digital BitBox does not allow users to restore a backup or seed via software.

## Note on `displayaddress`

The Digital BitBox does not have a screen to display an address on, so the implementation just raises an error stating this.
