# Python Jade Library

This is a slightly stripped down version of the official [Jade](https://github.com/Blockstream/Jade) python library.

This stripped down version was made from tag [0.1.32](https://github.com/Blockstream/Jade/releases/tag/0.1.32)

## Changes

- Removed BLE module, reducing transitive dependencies
- Have tcp connection (for simulator) respect passed timeout - backported from master
