from typing import Dict, Any, Optional, List
from ....errors import DeviceCompatibilityError, DeviceCompatibilityErrorType
from ....interfaces import IDeviceConnection
from ....common_utils import int_to_uint_byte, assert_condition
from ...utils.packet_version import PacketVersion, PacketVersionMap
from ...config import v3 as config_v3
from ...encoders.packet.packet import decode_payload_data, encode_packet
from .write_command import write_command
from .can_retry import can_retry


def get_command_output(
    connection: IDeviceConnection,
    version: PacketVersion,
    sequence_number: int,
    max_tries: int = 5,
    timeout: Optional[int] = None,
) -> Dict[str, Any]:
    assert_condition(connection, "Invalid connection")
    assert_condition(version, "Invalid version")
    assert_condition(sequence_number, "Invalid sequenceNumber")

    if version != PacketVersionMap.v3:
        raise DeviceCompatibilityError(
            DeviceCompatibilityErrorType.INVALID_SDK_OPERATION
        )

    usable_config = config_v3

    first_error: Optional[Exception] = None
    data_list: List[str] = []

    total_packets = 1
    current_packet = 1
    is_status_response = False

    while current_packet <= total_packets:
        tries = 1
        inner_max_tries = max_tries
        first_error = None
        is_success = False

        packets_list = encode_packet(
            raw_data=int_to_uint_byte(current_packet, 16),
            version=version,
            sequence_number=sequence_number,
            packet_type=usable_config.commands.PACKET_TYPE.CMD_OUTPUT_REQ,
        )

        if len(packets_list) > 1:
            raise Exception("Get Command Output exceeded 1 packet limit")

        packet = packets_list[0]

        while tries <= inner_max_tries and not is_success:
            try:
                received_packet = write_command(
                    connection=connection,
                    packet=packet,
                    version=version,
                    sequence_number=sequence_number,
                    ack_packet_types=[
                        usable_config.commands.PACKET_TYPE.CMD_OUTPUT,
                        usable_config.commands.PACKET_TYPE.STATUS,
                    ],
                    timeout=timeout,
                )

                data_list.insert(
                    received_packet["current_packet_number"] - 1,
                    received_packet["payload_data"],
                )
                total_packets = received_packet["total_packet_number"]
                current_packet = received_packet["current_packet_number"] + 1
                is_success = True
                is_status_response = (
                    received_packet["packet_type"]
                    == usable_config.commands.PACKET_TYPE.STATUS
                )

            except Exception as e:
                if not can_retry(e):
                    tries = inner_max_tries

                if not first_error:
                    first_error = e

            tries += 1

        if not is_success and first_error:
            raise first_error

    final_data = "".join(data_list)

    result = decode_payload_data(final_data, version)
    result["is_status"] = is_status_response

    return result
