from typing import List, Union
import re
from .assert_utils import assert_condition


def update_crc16(crc_param: int, byte: int) -> int:
    """
    Update CRC16 with a single byte.

    Args:
        crc_param: Current CRC value
        byte: Byte to update with

    Returns:
        int: Updated CRC value
    """
    assert_condition(crc_param is not None, "Invalid crcParam")
    assert_condition(byte is not None, "Invalid byte")

    input_val = byte | 0x100
    crc = crc_param

    while not (input_val & 0x10000):
        crc <<= 1
        input_val <<= 1
        if input_val & 0x100:
            crc += 1
        if crc & 0x10000:
            crc ^= 0x1021

    return crc & 0xFFFF


def crc16(data_buff: bytes) -> int:
    """
    Calculate CRC16 for a byte array.

    Args:
        data_buff: Byte array to calculate CRC for

    Returns:
        int: CRC16 value
    """
    assert_condition(data_buff is not None, "Data buffer cannot be empty")

    crc = 0
    for i in data_buff:
        crc = update_crc16(crc, i)

    crc = update_crc16(crc, 0)
    crc = update_crc16(crc, 0)

    return crc & 0xFFFF


def is_hex(maybe_hex: str) -> bool:
    """
    Check if a string is a valid hexadecimal.

    Args:
        maybe_hex: String to check

    Returns:
        bool: True if the string is valid hex, False otherwise
    """
    assert_condition(maybe_hex is not None, "Data cannot be empty")
    hex_str = maybe_hex
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    return bool(re.match(r"^[a-fA-F0-9]*$", hex_str))


def format_hex(maybe_hex: str) -> str:
    """
    Format a hexadecimal string.

    Args:
        maybe_hex: Hexadecimal string to format

    Returns:
        str: Formatted hexadecimal string
    """
    assert_condition(maybe_hex is not None, "Invalid hex")

    hex_str = maybe_hex
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]

    assert_condition(is_hex(hex_str), f"Invalid hex string: {maybe_hex}")

    if len(hex_str) % 2 != 0:
        hex_str = f"0{hex_str}"

    return hex_str


def hex_to_uint8array(data: str) -> bytes:
    """
    Convert a hexadecimal string to a byte array.

    Args:
        data: Hexadecimal string to convert

    Returns:
        bytes: Converted byte array
    """
    hex_str = format_hex(data)

    if len(hex_str) <= 0:
        return bytes()

    # Split the hex string into pairs of characters
    hex_pairs = [hex_str[i : i + 2] for i in range(0, len(hex_str), 2)]

    # Convert each pair to an integer and then to a byte
    return bytes(int(pair, 16) for pair in hex_pairs)


def uint8array_to_hex(data: bytes) -> str:
    """
    Convert a byte array to a hexadecimal string.

    Args:
        data: Byte array to convert

    Returns:
        str: Hexadecimal string
    """
    assert_condition(data is not None, "Invalid data")

    return "".join(f"{i:02x}" for i in data)


def pad_start(string: str, target_length: int, pad_string: str) -> str:
    """
    Pad the start of a string to a target length.

    Args:
        string: String to pad
        target_length: Target length of the padded string
        pad_string: String to use for padding

    Returns:
        str: Padded string
    """
    assert_condition(string is not None, "Invalid string")
    assert_condition(target_length is not None, "Invalid targetLength")
    assert_condition(pad_string is not None, "Invalid padString")

    if len(string) >= target_length:
        return string

    if len(pad_string) <= 0:
        raise ValueError("padString should not be empty")

    padding_needed = target_length - len(string)

    # Calculate how many times to repeat the pad_string
    repeat_count = (padding_needed + len(pad_string) - 1) // len(pad_string)
    padding = pad_string * repeat_count

    return padding[:padding_needed] + string


def int_to_uint_byte(num: Union[str, int], radix: int) -> str:
    """
    Convert an integer to a hexadecimal string with a specific bit width.

    Args:
        num: Number to convert
        radix: a bit of width (must be a multiple of 8)

    Returns:
        str: Hexadecimal string
    """
    assert_condition(num is not None, "Invalid number")
    assert_condition(radix is not None, "Invalid radix")

    if isinstance(num, str) and num.startswith("0x"):
        num_copy = int(num, 16)
    else:
        num_copy = int(num)
    if radix % 8 != 0:
        raise ValueError(f"Invalid radix: {radix}")

    if num_copy < 0:
        max_number = int("f" * (radix // 4), 16)
        num_copy = max_number - abs(num_copy) + 1

    val = format(num_copy, "x")
    no_of_zeroes = radix // 4 - len(val)

    if no_of_zeroes < 0:
        raise ValueError(f"Invalid serialization of data: {num} with radix {radix}")

    return "0" * no_of_zeroes + val


def hex_to_ascii(hex_str: str) -> str:
    """
    Convert a hexadecimal string to ASCII.

    Args:
        hex_str: Hexadecimal string to convert

    Returns:
        str: ASCII string
    """
    assert_condition(hex_str is not None, "Invalid string")

    hex_formatted = format_hex(hex_str)
    result = ""

    for i in range(0, len(hex_formatted), 2):
        char_code = int(hex_formatted[i : i + 2], 16)
        result += chr(char_code)

    return result


def num_to_byte_array(num: int) -> List[int]:
    """
    Convert a number to a byte array.

    Args:
        num: Number to convert

    Returns:
        List[int]: Byte array
    """
    n = num
    byte_array = []

    while n > 0:
        byte = n & 0xFF
        byte_array.append(byte)
        n = (n - byte) // 256

    return list(reversed(byte_array))
