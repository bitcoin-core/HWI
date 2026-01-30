
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
#   - bigger than minimum length, less than max
#   - 512-byte aligned
# - bootloader assumes the flash filesystem (FAT FS) follows the firmware.
# - timestamp is YYMMDDHHMMSS0000 in BCD


FW_HEADER_SIZE = 128
FW_HEADER_OFFSET = (0x4000-FW_HEADER_SIZE)

FW_HEADER_MAGIC = 0xCC001234

# Firmware Image Size

# arbitrary min size
FW_MIN_LENGTH = (256*1024)

# (mk1-3) absolute max size: 1MB flash - 32k for bootloader
# practical limit for our-protocol USB upgrades: 786432 (or else settings damaged)
FW_MAX_LENGTH = (0x100000 - 0x8000)

# .. for Mk4: 2Mbytes, less bootrom of 128k.
FW_MAX_LENGTH_MK4 = (0x200000 - 0x20000)

# Arguments to be used w/ python's struct module.
FWH_PY_FORMAT = "<I8s8sIIII8s20s64s"
FWH_PY_VALUES = "magic_value timestamp version_string pubkey_num firmware_length install_flags hw_compat best_ts future signature"
FWH_NUM_FUTURE = 7

# offset of pubkey number
FWH_PK_NUM_OFFSET = 20

# Bits in install_flags
FWHIF_HIGH_WATER = 0x01
FWHIF_BEST_TS = 0x02

# Bits in hw_compat
MK_1_OK = 0x01
MK_2_OK = 0x02
MK_3_OK = 0x04
MK_4_OK = 0x08
MK_Q1_OK = 0x10
# RFU:
MK_6_OK = 0x20

# EOF