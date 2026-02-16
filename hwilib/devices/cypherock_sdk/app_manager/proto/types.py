# UpdateFirmwareStatus enum - used for status tracking during firmware update
from enum import Enum

class UpdateFirmwareStatus(Enum):
    UPDATE_FIRMWARE_STATUS_INIT = 0
    UPDATE_FIRMWARE_STATUS_USER_CONFIRMED = 1
    UNRECOGNIZED = -1

__all__ = ["UpdateFirmwareStatus"]
