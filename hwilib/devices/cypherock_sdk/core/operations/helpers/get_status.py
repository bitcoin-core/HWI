from typing import Dict, Any, Optional
from ....errors import DeviceCompatibilityError, DeviceCompatibilityErrorType
from ....interfaces import IDeviceConnection
from ....common_utils import assert_condition
from ...config import v3 as config_v3
from ...utils.packet_version import PacketVersion, PacketVersionMap
from ...encoders.packet.packet import decode_payload_data, encode_packet
from .write_command import write_command
from .can_retry import can_retry


async def get_status(
    connection: IDeviceConnection,
    version: PacketVersion,
    max_tries: int = 5,
    timeout: Optional[int] = None,
) -> Dict[str, Any]:
    assert_condition(connection, "Invalid connection")
    assert_condition(version, "Invalid version")

    if version != PacketVersionMap.v3:
        raise DeviceCompatibilityError(
            DeviceCompatibilityErrorType.INVALID_SDK_OPERATION
        )

    usable_config = config_v3

    packets_list = encode_packet(
        raw_data="",
        version=version,
        sequence_number=-1,
        packet_type=usable_config.commands.PACKET_TYPE.STATUS_REQ,
    )

    if len(packets_list) == 0:
        raise Exception("Could not create packets")

    if len(packets_list) > 1:
        raise Exception("Status command has multiple packets")

    first_error: Optional[Exception] = None

    tries = 1
    inner_max_tries = max_tries
    first_error = None
    is_success = False
    final_data = ""

    packet = packets_list[0]

    while tries <= inner_max_tries and not is_success:
        try:
            received_packet = await write_command(
                connection=connection,
                packet=packet,
                version=version,
                sequence_number=-1,
                ack_packet_types=[usable_config.commands.PACKET_TYPE.STATUS],
                timeout=timeout,
            )
            final_data = received_packet["payload_data"]
            is_success = True

        except Exception as e:
            if not can_retry(e):
                tries = inner_max_tries

            if not first_error:
                first_error = e

        tries += 1

    if not is_success and first_error:
        raise first_error

    return decode_payload_data(final_data, version)
