"""Encoding helpers for opaque Ledger policy registrations."""

from typing import List, Sequence, Tuple

from ..errors import BadArgumentError


def _encode_fields(fields: Sequence[bytes]) -> bytes:
    encoded = bytearray()
    for field in fields:
        if len(field) > 255:
            raise BadArgumentError("Ledger policy registration fields cannot exceed 255 bytes")
        encoded.append(len(field))
        encoded.extend(field)
    return bytes(encoded)


def _decode_fields(encoded: bytes) -> List[bytes]:
    fields: List[bytes] = []
    offset = 0
    while offset < len(encoded):
        field_length = encoded[offset]
        offset += 1
        field_end = offset + field_length
        if field_end > len(encoded):
            raise BadArgumentError("Invalid Ledger policy registration")
        fields.append(encoded[offset:field_end])
        offset = field_end
    return fields


def encode_policy_registration(device_registration: bytes, policy_name: str) -> str:
    """Encode the device registration and policy name as an opaque hex string."""

    try:
        name = policy_name.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise BadArgumentError("Ledger policy names must use Latin-1 characters") from exc
    return _encode_fields([device_registration, name]).hex()


def decode_policy_registration(registration: str) -> Tuple[bytes, str]:
    """Decode the device registration and policy name from an opaque hex string."""

    try:
        fields = _decode_fields(bytes.fromhex(registration))
    except ValueError as exc:
        raise BadArgumentError("Invalid Ledger policy registration") from exc
    if len(fields) < 2:
        raise BadArgumentError("Invalid Ledger policy registration")
    return fields[0], fields[1].decode("latin-1")
