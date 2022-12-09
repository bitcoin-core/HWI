"""
Bitcoin Script utilities
************************
"""

from typing import (
    Optional,
    Sequence,
    Tuple,
)


def is_opreturn(script: bytes) -> bool:
    """
    Determine whether a script is an OP_RETURN output script.

    :param script: The script
    :returns: Whether the script is an OP_RETURN output script
    """
    return script[0] == 0x6a


def is_p2sh(script: bytes) -> bool:
    """
    Determine whether a script is a P2SH output script.

    :param script: The script
    :returns: Whether the script is a P2SH output script
    """
    return len(script) == 23 and script[0] == 0xa9 and script[1] == 0x14 and script[22] == 0x87


def is_p2pkh(script: bytes) -> bool:
    """
    Determine whether a script is a P2PKH output script.

    :param script: The script
    :returns: Whether the script is a P2PKH output script
    """
    return len(script) == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[2] == 0x14 and script[23] == 0x88 and script[24] == 0xac


def is_p2pk(script: bytes) -> bool:
    """
    Determine whether a script is a P2PK output script.

    :param script: The script
    :returns: Whether the script is a P2PK output script
    """
    return (len(script) == 35 or len(script) == 67) and (script[0] == 0x21 or script[0] == 0x41) and script[-1] == 0xac


def is_witness(script: bytes) -> Tuple[bool, int, bytes]:
    """
    Determine whether a script is a segwit output script.
    If so, also returns the witness version and witness program.

    :param script: The script
    :returns: A tuple of a bool indicating whether the script is a segwit output script,
        an int representing the witness version,
        and the bytes of the witness program.
    """
    if len(script) < 4 or len(script) > 42:
        return (False, 0, b"")

    if script[0] != 0 and (script[0] < 81 or script[0] > 96):
        return (False, 0, b"")

    if script[1] + 2 == len(script):
        return (True, script[0] - 0x50 if script[0] else 0, script[2:])

    return (False, 0, b"")


def is_p2wpkh(script: bytes) -> bool:
    """
    Determine whether a script is a P2WPKH output script.

    :param script: The script
    :returns: Whether the script is a P2WPKH output script
    """
    is_wit, wit_ver, wit_prog = is_witness(script)
    if not is_wit:
        return False
    elif wit_ver != 0:
        return False
    return len(wit_prog) == 20


def is_p2wsh(script: bytes) -> bool:
    """
    Determine whether a script is a P2WSH output script.

    :param script: The script
    :returns: Whether the script is a P2WSH output script
    """
    is_wit, wit_ver, wit_prog = is_witness(script)
    if not is_wit:
        return False
    elif wit_ver != 0:
        return False
    return len(wit_prog) == 32

def is_p2tr(script: bytes) -> bool:
    """
    Determine whether a script is a P2TR output script.

    :param script: The script
    :returns: Whether the script is a P2TR output script
    """
    is_wit, wit_ver, wit_prog = is_witness(script)
    if not is_wit:
        return False
    elif wit_ver != 1:
        return False
    return len(wit_prog) == 32


# Only handles up to 15 of 15. Returns None if this script is not a
# multisig script. Returns (m, pubkeys) otherwise.
def parse_multisig(script: bytes) -> Optional[Tuple[int, Sequence[bytes]]]:
    """
    Determine whether a script is a multisig script. If so, determine the parameters of that multisig.

    :param script: The script
    :returns: ``None`` if the script is not multisig.
        If multisig, returns a tuple of the number of signers required,
        and a sequence of public key bytes.
    """
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
