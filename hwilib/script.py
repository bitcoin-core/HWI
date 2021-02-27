import struct
from enum import IntEnum
from typing import Optional


class OpCode(IntEnum):
    # push value
    OP_0 = 0x00
    OP_FALSE = OP_0
    OP_PUSHDATA1 = 0x4c
    OP_PUSHDATA2 = 0x4d
    OP_PUSHDATA4 = 0x4e
    OP_1NEGATE = 0x4f
    OP_RESERVED = 0x50
    OP_1 = 0x51
    OP_TRUE = OP_1
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_6 = 0x56
    OP_7 = 0x57
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5a
    OP_11 = 0x5b
    OP_12 = 0x5c
    OP_13 = 0x5d
    OP_14 = 0x5e
    OP_15 = 0x5f
    OP_16 = 0x60

    # control
    OP_NOP = 0x61
    OP_VER = 0x62
    OP_IF = 0x63
    OP_NOTIF = 0x64
    OP_VERIF = 0x65
    OP_VERNOTIF = 0x66
    OP_ELSE = 0x67
    OP_ENDIF = 0x68
    OP_VERIFY = 0x69
    OP_RETURN = 0x6a

    # stack ops
    OP_TOALTSTACK = 0x6b
    OP_FROMALTSTACK = 0x6c
    OP_2DROP = 0x6d
    OP_2DUP = 0x6e
    OP_3DUP = 0x6f
    OP_2OVER = 0x70
    OP_2ROT = 0x71
    OP_2SWAP = 0x72
    OP_IFDUP = 0x73
    OP_DEPTH = 0x74
    OP_DROP = 0x75
    OP_DUP = 0x76
    OP_NIP = 0x77
    OP_OVER = 0x78
    OP_PICK = 0x79
    OP_ROLL = 0x7a
    OP_ROT = 0x7b
    OP_SWAP = 0x7c
    OP_TUCK = 0x7d

    # splice ops
    OP_CAT = 0x7e
    OP_SUBSTR = 0x7f
    OP_LEFT = 0x80
    OP_RIGHT = 0x81
    OP_SIZE = 0x82

    # bit logic
    OP_INVERT = 0x83
    OP_AND = 0x84
    OP_OR = 0x85
    OP_XOR = 0x86
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88
    OP_RESERVED1 = 0x89
    OP_RESERVED2 = 0x8a

    # numeric
    OP_1ADD = 0x8b
    OP_1SUB = 0x8c
    OP_2MUL = 0x8d
    OP_2DIV = 0x8e
    OP_NEGATE = 0x8f
    OP_ABS = 0x90
    OP_NOT = 0x91
    OP_0NOTEQUAL = 0x92

    OP_ADD = 0x93
    OP_SUB = 0x94
    OP_MUL = 0x95
    OP_DIV = 0x96
    OP_MOD = 0x97
    OP_LSHIFT = 0x98
    OP_RSHIFT = 0x99

    OP_BOOLAND = 0x9a
    OP_BOOLOR = 0x9b
    OP_NUMEQUAL = 0x9c
    OP_NUMEQUALVERIFY = 0x9d
    OP_NUMNOTEQUAL = 0x9e
    OP_LESSTHAN = 0x9f
    OP_GREATERTHAN = 0xa0
    OP_LESSTHANOREQUAL = 0xa1
    OP_GREATERTHANOREQUAL = 0xa2
    OP_MIN = 0xa3
    OP_MAX = 0xa4

    OP_WITHIN = 0xa5

    # crypto
    OP_RIPEMD160 = 0xa6
    OP_SHA1 = 0xa7
    OP_SHA256 = 0xa8
    OP_HASH160 = 0xa9
    OP_HASH256 = 0xaa
    OP_CODESEPARATOR = 0xab
    OP_CHECKSIG = 0xac
    OP_CHECKSIGVERIFY = 0xad
    OP_CHECKMULTISIG = 0xae
    OP_CHECKMULTISIGVERIFY = 0xaf

    # expansion
    OP_NOP1 = 0xb0
    OP_CHECKLOCKTIMEVERIFY = 0xb1
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY
    OP_CHECKSEQUENCEVERIFY = 0xb2
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY
    OP_NOP4 = 0xb3
    OP_NOP5 = 0xb4
    OP_NOP6 = 0xb5
    OP_NOP7 = 0xb6
    OP_NOP8 = 0xb7
    OP_NOP9 = 0xb8
    OP_NOP10 = 0xb9

    # qtum contract
    OP_CREATE = 0xc1
    OP_CALL = 0xc2
    OP_SPEND = 0xc3
    OP_SENDER = 0xc4

    OP_INVALIDOPCODE = 0xff

    def hex(self) -> str:
        return bytes([self]).hex()


class MalformedScript(Exception):
    pass


def rev_hex(s: str) -> str:
    return bytes.fromhex(s)[::-1].hex()


def int_to_hex(i: int, length: int = 1) -> str:
    """Converts int to little-endian hex string.
    `length` is the number of bytes available
    """
    if not isinstance(i, int):
        raise TypeError('{} instead of int'.format(i))
    range_size = pow(256, length)
    if i < -(range_size // 2) or i >= range_size:
        raise OverflowError('cannot convert int {} to hex ({} bytes)'.format(i, length))
    if i < 0:
        # two's complement
        i = range_size + i
    s = hex(i)[2:].rstrip('L')
    s = "0" * (2 * length - len(s)) + s
    return rev_hex(s)


def _op_push(i: int) -> str:
    if i < OpCode.OP_PUSHDATA1:
        return int_to_hex(i)
    elif i <= 0xff:
        return OpCode.OP_PUSHDATA1.hex() + int_to_hex(i, 1)
    elif i <= 0xffff:
        return OpCode.OP_PUSHDATA2.hex() + int_to_hex(i, 2)
    else:
        return OpCode.OP_PUSHDATA4.hex() + int_to_hex(i, 4)


def push_data(data: str) -> str:
    data = bytes.fromhex(data)
    data_len = len(data)
    return _op_push(data_len) + data.hex()


def parse_script(script: bytes):
    i = 0
    while i < len(script):
        vch = None
        opcode = script[i]
        i += 1

        if opcode <= OpCode.OP_PUSHDATA4:
            nSize = opcode
            if opcode == OpCode.OP_PUSHDATA1:
                try: nSize = script[i]
                except IndexError: raise MalformedScript()
                i += 1
            elif opcode == OpCode.OP_PUSHDATA2:
                try: (nSize,) = struct.unpack_from('<H', script, i)
                except struct.error: raise MalformedScript()
                i += 2
            elif opcode == OpCode.OP_PUSHDATA4:
                try: (nSize,) = struct.unpack_from('<I', script, i)
                except struct.error: raise MalformedScript()
                i += 4
            vch = script[i:i + nSize]
            i += nSize

        yield opcode, vch, i


def decode_opsender_script(script: bytes) -> Optional[list]:
    try:
        decoded = [x for x in parse_script(script)]
    except MalformedScript:
        return None

    num_elements = len(decoded)
    if num_elements == 0:
        return None
    is_opcall = decoded[-1][0] == OpCode.OP_CALL
    is_opcreate = decoded[-1][0] == OpCode.OP_CREATE

    if ((is_opcall and num_elements == 10) or (is_opcreate and num_elements == 9)) \
            and decoded[0] == (1, b'\x01', 2) \
            and decoded[1][0] == 0x14 \
            and decoded[3][0] == OpCode.OP_SENDER:
        return decoded
    return None


def update_opsender_sig(script: bytes, sig: bytes) -> bytes:
    decoded = decode_opsender_script(script)
    if decoded is None:
        # _logger.debug("input script does not match op_sender, will not update")
        return script
    result = script[0:decoded[1][2]]
    result += bytes.fromhex(push_data(sig.hex()))
    result += script[decoded[2][2]:]
    return result
