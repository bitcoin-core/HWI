# Autogen'ed file, don't edit. See bootloader/mk-sigheader.h for original


# Our simple firmware header.
# Although called a header, this data is placed into the middle of the binary.
# It is located at start of firmware + 16k - sizeof(heaer). This is a gap unused in normal
# micropython layout. Exactly the last 64 bytes (signature) should be left out of
# the checksum. We do checksum areas beyond the end of the last byte of firmware (up to length)
# and expect those regions to be unprogrammed flash (ones).
# - timestamp must increase with each upgrade (downgrade protection)
# - version_string is for humans only
# - pubkey_num indicates which pubkey was used for signature
# - firmware_length, must be:
# - bigger than minimum length, less than max
# - 512-byte aligned
# - bootloader assumes the flash filesystem (FAT FS) follows the firmware.
# - this C header file is somewhat parsed and used by python signature-adding code
# - timestamp is YYMMDDHHMMSS0000 in BCD


FW_HEADER_SIZE = 128
FW_HEADER_OFFSET = (0x4000-FW_HEADER_SIZE)

FW_HEADER_MAGIC = 0xCC001234

# arbitrary min size
FW_MIN_LENGTH = (256*1024)
# absolute max: 1MB flash - 32k for bootloader
# practical limit for our-protocol USB upgrades: 786432 (or else settings damaged)
FW_MAX_LENGTH = (0x100000 - 0x8000)

# Arguments to be used w/ python's struct module.
FWH_PY_FORMAT = "<I8s8sII36s64s"
FWH_PY_VALUES = "magic_value timestamp version_string pubkey_num firmware_length future signature"
FWH_NUM_FUTURE = 9
FWH_PK_NUM_OFFSET = 20

# There is a copy of the header at this location in RAM, copied by bootloader
# **after** it has been verified. Cannot write to this area, or you will be reset!
RAM_HEADER_BASE = 0x10007c20

# Original copy of header, as recorded in flash/firmware file.
FLASH_HEADER_BASE = 0x0800bf80

# EOF
