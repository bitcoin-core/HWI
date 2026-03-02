import time
from typing import TypedDict, List, Dict
from enum import Enum
from ...config import v3
from ....common_utils import (
    assert_condition,
    is_hex,
    uint8array_to_hex,
    hex_to_uint8array,
    int_to_uint_byte,
    crc16,
)
from ...utils.packet_version import PacketVersion, PacketVersionMap
from ....errors import DeviceCompatibilityError, DeviceCompatibilityErrorType


class DecodedPacketData(TypedDict):
    start_of_frame: str
    current_packet_number: int
    total_packet_number: int
    payload_data: str
    crc: str
    sequence_number: int
    packet_type: int
    error_list: List[str]
    timestamp: int


class ErrorPacketRejectReason(Enum):
    NO_ERROR = 0
    CHECKSUM_ERROR = 1
    BUSY_PREVIOUS_CMD = 2
    OUT_OF_ORDER_CHUNK = 3
    INVALID_CHUNK_COUNT = 4
    INVALID_SEQUENCE_NO = 5
    INVALID_PAYLOAD_LENGTH = 6
    APP_BUFFER_BLOCKED = 7
    NO_MORE_CHUNKS = 8
    INVALID_PACKET_TYPE = 9
    INVALID_CHUNK_NO = 10
    INCOMPLETE_PACKET = 11


RejectReasonToMsgMap: Dict[ErrorPacketRejectReason, str] = {
    ErrorPacketRejectReason.NO_ERROR: "No error",
    ErrorPacketRejectReason.CHECKSUM_ERROR: "Checksum error",
    ErrorPacketRejectReason.BUSY_PREVIOUS_CMD: "Device is busy on previous command",
    ErrorPacketRejectReason.OUT_OF_ORDER_CHUNK: "Chunk out of order",
    ErrorPacketRejectReason.INVALID_CHUNK_COUNT: "Invalid chunk count",
    ErrorPacketRejectReason.INVALID_SEQUENCE_NO: "Invalid sequence number",
    ErrorPacketRejectReason.INVALID_PAYLOAD_LENGTH: "Invalid payload length",
    ErrorPacketRejectReason.APP_BUFFER_BLOCKED: "Application buffer blocked",
    ErrorPacketRejectReason.NO_MORE_CHUNKS: "No more chunks",
    ErrorPacketRejectReason.INVALID_PACKET_TYPE: "Invalid packet type",
    ErrorPacketRejectReason.INVALID_CHUNK_NO: "Invalid chunk number",
    ErrorPacketRejectReason.INCOMPLETE_PACKET: "Incomplete packet",
}


def encode_payload_data(
    raw_data: str,
    protobuf_data: str,
    version: PacketVersion,
) -> str:
    assert_condition(raw_data, "Invalid rawData")
    assert_condition(protobuf_data, "Invalid protobufData")
    assert_condition(version, "Invalid version")
    assert_condition(is_hex(raw_data), "Invalid hex in rawData")
    assert_condition(is_hex(protobuf_data), "Invalid hex in protobufData")

    if version != PacketVersionMap.v3:
        raise DeviceCompatibilityError(
            DeviceCompatibilityErrorType.INVALID_SDK_OPERATION,
        )

    if len(raw_data) == 0 and len(protobuf_data) == 0:
        return ""

    usable_config = v3

    serialized_raw_data_length = int_to_uint_byte(
        len(raw_data) // 2,
        usable_config.radix.data_size,
    )
    serialized_protobuf_data_length = int_to_uint_byte(
        len(protobuf_data) // 2,
        usable_config.radix.data_size,
    )

    return (
        serialized_protobuf_data_length
        + serialized_raw_data_length
        + protobuf_data
        + raw_data
    )


def encode_packet(
    raw_data: str = "",
    proto_data: str = "",
    version: PacketVersion = PacketVersionMap.v3,
    sequence_number: int = 0,
    packet_type: int = 0,
) -> List[bytes]:
    assert_condition(raw_data or proto_data, "Invalid data")
    assert_condition(version, "Invalid version")
    assert_condition(sequence_number is not None, "Invalid sequenceNumber")
    assert_condition(packet_type is not None, "Invalid packetType")

    if raw_data:
        assert_condition(is_hex(raw_data), "Invalid hex in raw data")
    if proto_data:
        assert_condition(is_hex(proto_data), "Invalid hex in proto data")

    assert_condition(packet_type > 0, "Packet type cannot be negative")

    if version != PacketVersionMap.v3:
        raise DeviceCompatibilityError(
            DeviceCompatibilityErrorType.INVALID_SDK_OPERATION,
        )

    usable_config = v3

    serialized_sequence_number = int_to_uint_byte(
        sequence_number,
        usable_config.radix.sequence_number,
    )
    serialized_packet_type = int_to_uint_byte(
        packet_type,
        usable_config.radix.packet_type,
    )

    chunk_size = usable_config.constants.CHUNK_SIZE
    start_of_frame = usable_config.constants.START_OF_FRAME

    serialized_data = encode_payload_data(
        raw_data,
        proto_data,
        version,
    )

    rounds = (len(serialized_data) + chunk_size - 1) // chunk_size
    has_no_data = len(serialized_data) == 0
    if has_no_data:
        rounds = 1

    packet_list: List[bytes] = []

    for i in range(1, rounds + 1):
        current_packet_number = int_to_uint_byte(
            i,
            usable_config.radix.current_packet_number,
        )
        total_packet_number = int_to_uint_byte(
            rounds,
            usable_config.radix.total_packet,
        )
        data_chunk = serialized_data[
            (i - 1) * chunk_size: (i - 1) * chunk_size + chunk_size
        ]
        payload = data_chunk
        payload_length = int_to_uint_byte(
            len(data_chunk) // 2,
            usable_config.radix.payload_length,
        )
        # Match TypeScript behavior: Date.now().toString().slice(0, timestampLength / 4)
        timestamp_ms = int(time.time() * 1000)  # JavaScript Date.now() equivalent
        timestamp_str = str(timestamp_ms)[: usable_config.radix.timestamp_length // 4]
        serialized_timestamp = int_to_uint_byte(
            int(timestamp_str),
            usable_config.radix.timestamp_length,
        )

        comm_data = (
            current_packet_number
            + total_packet_number
            + serialized_sequence_number
            + serialized_packet_type
            + serialized_timestamp
            + payload_length
            + payload
        )
        crc = int_to_uint_byte(
            crc16(hex_to_uint8array(comm_data)),
            usable_config.radix.crc,
        )
        packet = start_of_frame + crc + comm_data
        packet_list.append(hex_to_uint8array(packet))

    return packet_list


def decode_packet(
    param: bytes,
    version: PacketVersion,
) -> List[DecodedPacketData]:
    if version != PacketVersionMap.v3:
        raise DeviceCompatibilityError(
            DeviceCompatibilityErrorType.INVALID_SDK_OPERATION,
        )

    usable_config = v3
    start_of_frame = usable_config.constants.START_OF_FRAME

    data = uint8array_to_hex(param).lower()
    packet_list: List[DecodedPacketData] = []
    offset = data.find(start_of_frame)

    while len(data) > 0:
        offset = data.find(start_of_frame)
        if offset == -1:
            return packet_list

        # Add bounds checking for all field reads
        if offset + len(start_of_frame) > len(data):
            break
        start_of_frame = data[offset: offset + len(start_of_frame)]
        offset += len(start_of_frame)

        if offset + usable_config.radix.crc // 4 > len(data):
            break
        crc = data[offset: offset + usable_config.radix.crc // 4]
        offset += usable_config.radix.crc // 4

        if offset + usable_config.radix.current_packet_number // 4 > len(data):
            break
        current_packet_number = int(
            data[offset: offset + usable_config.radix.current_packet_number // 4],
            16,
        )
        offset += usable_config.radix.current_packet_number // 4

        if offset + usable_config.radix.total_packet // 4 > len(data):
            break
        total_packet_number = int(
            data[offset: offset + usable_config.radix.total_packet // 4],
            16,
        )
        offset += usable_config.radix.total_packet // 4

        if offset + usable_config.radix.sequence_number // 4 > len(data):
            break
        sequence_number = int(
            data[offset: offset + usable_config.radix.sequence_number // 4],
            16,
        )
        offset += usable_config.radix.sequence_number // 4

        if offset + usable_config.radix.packet_type // 4 > len(data):
            break
        packet_type = int(
            data[offset: offset + usable_config.radix.packet_type // 4],
            16,
        )
        offset += usable_config.radix.packet_type // 4

        if offset + usable_config.radix.timestamp_length // 4 > len(data):
            break
        timestamp = int(
            data[offset: offset + usable_config.radix.timestamp_length // 4],
            16,
        )
        offset += usable_config.radix.timestamp_length // 4

        if offset + usable_config.radix.payload_length // 4 > len(data):
            break
        payload_length = int(
            data[offset: offset + usable_config.radix.payload_length // 4],
            16,
        )
        offset += usable_config.radix.payload_length // 4

        payload_data = ""
        if payload_length != 0:
            available_length = len(data) - offset
            read_length = min(payload_length * 2, available_length)
            if read_length > 0:
                payload_data = data[offset: offset + read_length]
                offset += read_length
        data = data[offset:]

        comm_data = (
            int_to_uint_byte(
                current_packet_number, usable_config.radix.current_packet_number
            )
            + int_to_uint_byte(total_packet_number, usable_config.radix.total_packet)
            + int_to_uint_byte(sequence_number, usable_config.radix.sequence_number)
            + int_to_uint_byte(packet_type, usable_config.radix.packet_type)
            + int_to_uint_byte(timestamp, usable_config.radix.timestamp_length)
            + int_to_uint_byte(payload_length, usable_config.radix.payload_length)
            + payload_data
        )
        actual_crc = int_to_uint_byte(
            crc16(hex_to_uint8array(comm_data)),
            usable_config.radix.crc,
        )

        error_list = []
        if start_of_frame.upper() != start_of_frame.upper():
            error_list.append("Invalid Start of frame")
        if current_packet_number > total_packet_number:
            error_list.append(
                "current_packet_number is greater than total_packet_number"
            )
        if actual_crc.upper() != crc.upper():
            error_list.append("invalid crc")

        packet_list.append(
            DecodedPacketData(
                start_of_frame=start_of_frame,
                current_packet_number=current_packet_number,
                total_packet_number=total_packet_number,
                crc=crc,
                payload_data=payload_data,
                error_list=error_list,
                sequence_number=sequence_number,
                packet_type=packet_type,
                timestamp=timestamp,
            )
        )
    return packet_list


def decode_payload_data(payload: str, version: PacketVersion) -> Dict[str, str]:
    assert_condition(payload, "Invalid payload")
    assert_condition(version, "Invalid version")
    assert_condition(is_hex(payload), "Invalid hex in payload")

    if version != PacketVersionMap.v3:
        raise DeviceCompatibilityError(
            DeviceCompatibilityErrorType.INVALID_SDK_OPERATION,
        )

    usable_config = v3
    payload_offset = 0

    data_size_half = usable_config.radix.data_size // 4

    protobuf_data_size = int(
        payload[payload_offset: payload_offset + data_size_half], 16
    )
    payload_offset += data_size_half

    raw_data_size = int(payload[payload_offset: payload_offset + data_size_half], 16)
    payload_offset += data_size_half

    protobuf_data = payload[payload_offset: payload_offset + protobuf_data_size * 2]
    payload_offset += protobuf_data_size * 2

    raw_data = payload[payload_offset: payload_offset + raw_data_size * 2]
    payload_offset += raw_data_size * 2

    return {
        "protobuf_data": protobuf_data,
        "raw_data": raw_data,
    }
