from typing import (
    Optional,
    Sequence,
    Tuple,
)


def is_opreturn(script: bytes) -> bool:
    return script[0] == 0x6a


def is_p2sh(script: bytes) -> bool:
    return len(script) == 23 and script[0] == 0xa9 and script[1] == 0x14 and script[22] == 0x87


def is_p2pkh(script: bytes) -> bool:
    return len(script) == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[2] == 0x14 and script[23] == 0x88 and script[24] == 0xac


def is_p2pk(script: bytes) -> bool:
    return (len(script) == 35 or len(script) == 67) and (script[0] == 0x21 or script[0] == 0x41) and script[-1] == 0xac


def is_witness(script: bytes) -> Tuple[bool, int, bytes]:
    if len(script) < 4 or len(script) > 42:
        return (False, 0, b"")

    if script[0] != 0 and (script[0] < 81 or script[0] > 96):
        return (False, 0, b"")

    if script[1] + 2 == len(script):
        return (True, script[0] - 0x50 if script[0] else 0, script[2:])

    return (False, 0, b"")


def is_p2wpkh(script: bytes) -> bool:
    is_wit, wit_ver, wit_prog = is_witness(script)
    if not is_wit:
        return False
    elif wit_ver != 0:
        return False
    return len(wit_prog) == 20


def is_p2wsh(script: bytes) -> bool:
    is_wit, wit_ver, wit_prog = is_witness(script)
    if not is_wit:
        return False
    elif wit_ver != 0:
        return False
    return len(wit_prog) == 32


# Only handles up to 15 of 15. Returns None if this script is not a
# multisig script. Returns (m, pubkeys) otherwise.
def parse_multisig(script: bytes) -> Optional[Tuple[int, Sequence[bytes]]]:
    # Get m
    m = script[0] - 80
    if m < 1 or m > 15:
        return None

    # Get pubkeys
    pubkeys = []
    offset = 1
    while True:
        pubkey_len = script[offset]
        if pubkey_len != 33:
            break
        offset += 1
        pubkeys.append(script[offset:offset + 33])
        offset += 33

    # Check things at the end
    n = script[offset] - 80
    if n != len(pubkeys):
        return None
    offset += 1
    op_cms = script[offset]
    if op_cms != 174:
        return None

    return (m, pubkeys)
