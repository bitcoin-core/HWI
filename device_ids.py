# Contains the arrays of device IDs. This is to avoid TREZOR and KeepKey
# library incompatibility.

ledger_device_ids = [
                    (0x2581, 0x2b7c),
                    (0x2581, 0x3b7c),
                    (0x2581, 0x4b7c),
                    (0x2c97, 0x0001),
                    (0x2581, 0x1807)]

digitalbitbox_device_ids = [
                            (0x03eb, 0x2402)
                            ]

trezor_device_ids = [
    (0x534c, 0x0001),  # TREZOR
    (0x1209, 0x53c0),  # TREZORv2 Bootloader
    (0x1209, 0x53c1),  # TREZORv2
]

keepkey_device_ids = [
    (0x2B24, 0x0001),  # KeepKey
]
