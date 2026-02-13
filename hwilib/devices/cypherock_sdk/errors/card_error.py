from enum import Enum
from ..core.encoders.proto.generated.error_pb2 import CardError
from .sub_error import SubErrorToMap, SubErrorDetail


class CardAppErrorType(Enum):
    UNKNOWN = "APP_0400_001"
    NOT_PAIRED = "APP_0400_002"
    SW_INCOMPATIBLE_APPLET = "APP_0400_003"
    SW_NULL_POINTER_EXCEPTION = "APP_0400_004"
    SW_TRANSACTION_EXCEPTION = "APP_0400_005"
    SW_FILE_INVALID = "APP_0400_006"
    SW_SECURITY_CONDITIONS_NOT_SATISFIED = "APP_0400_007"
    SW_CONDITIONS_NOT_SATISFIED = "APP_0400_008"
    SW_WRONG_DATA = "APP_0400_009"
    SW_FILE_NOT_FOUND = "APP_0400_010"
    SW_RECORD_NOT_FOUND = "APP_0400_011"
    SW_FILE_FULL = "APP_0400_012"
    SW_CORRECT_LENGTH_00 = "APP_0400_013"
    SW_INVALID_INS = "APP_0400_014"
    SW_NOT_PAIRED = "APP_0400_015"
    SW_CRYPTO_EXCEPTION = "APP_0400_016"
    POW_SW_WALLET_LOCKED = "APP_0400_017"
    SW_INS_BLOCKED = "APP_0400_018"
    SW_OUT_OF_BOUNDARY = "APP_0400_019"
    UNRECOGNIZED = "APP_0400_000"


cardErrorTypeDetails = SubErrorToMap[int]()

cardErrorTypeDetails[CardError.CARD_ERROR_UNKNOWN] = SubErrorDetail(
    CardAppErrorType.UNKNOWN.value, "Unknown card error"
)
cardErrorTypeDetails[CardError.CARD_ERROR_NOT_PAIRED] = SubErrorDetail(
    CardAppErrorType.NOT_PAIRED.value, "Card is not paired"
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_INCOMPATIBLE_APPLET] = SubErrorDetail(
    CardAppErrorType.SW_INCOMPATIBLE_APPLET.value, "Incompatible applet version"
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_NULL_POINTER_EXCEPTION] = SubErrorDetail(
    CardAppErrorType.SW_NULL_POINTER_EXCEPTION.value, "Null pointer exception"
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_TRANSACTION_EXCEPTION] = SubErrorDetail(
    CardAppErrorType.SW_TRANSACTION_EXCEPTION.value, "Operation failed on card (Tx Exp)"
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_FILE_INVALID] = SubErrorDetail(
    CardAppErrorType.SW_FILE_INVALID.value, "Tapped card family id mismatch"
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_SECURITY_CONDITIONS_NOT_SATISFIED] = (
    SubErrorDetail(
        CardAppErrorType.SW_SECURITY_CONDITIONS_NOT_SATISFIED.value,
        "Security conditions not satisfied, i.e. pairing session invalid",
    )
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_CONDITIONS_NOT_SATISFIED] = SubErrorDetail(
    CardAppErrorType.SW_CONDITIONS_NOT_SATISFIED.value, "Wrong card sequence"
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_WRONG_DATA] = SubErrorDetail(
    CardAppErrorType.SW_WRONG_DATA.value, "Invalid APDU length"
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_FILE_NOT_FOUND] = SubErrorDetail(
    CardAppErrorType.SW_FILE_NOT_FOUND.value, "Corrupted card"
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_RECORD_NOT_FOUND] = SubErrorDetail(
    CardAppErrorType.SW_RECORD_NOT_FOUND.value, "Wallet does not exist on device"
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_FILE_FULL] = SubErrorDetail(
    CardAppErrorType.SW_FILE_FULL.value, "Card is full"
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_CORRECT_LENGTH_00] = SubErrorDetail(
    CardAppErrorType.SW_CORRECT_LENGTH_00.value, "Incorrect pin entered"
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_INVALID_INS] = SubErrorDetail(
    CardAppErrorType.SW_INVALID_INS.value, "Applet unknown error"
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_NOT_PAIRED] = SubErrorDetail(
    CardAppErrorType.SW_NOT_PAIRED.value, "Card pairing to device missing"
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_CRYPTO_EXCEPTION] = SubErrorDetail(
    CardAppErrorType.SW_CRYPTO_EXCEPTION.value, "Operation failed on card (Crypto Exp)"
)
cardErrorTypeDetails[CardError.CARD_ERROR_POW_SW_WALLET_LOCKED] = SubErrorDetail(
    CardAppErrorType.POW_SW_WALLET_LOCKED.value,
    "Locked wallet status word, POW meaning proof of word",
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_INS_BLOCKED] = SubErrorDetail(
    CardAppErrorType.SW_INS_BLOCKED.value, "Card health critical, migration required"
)
cardErrorTypeDetails[CardError.CARD_ERROR_SW_OUT_OF_BOUNDARY] = SubErrorDetail(
    CardAppErrorType.SW_OUT_OF_BOUNDARY.value,
    "Operation failed on card (Out of boundary)",
)
