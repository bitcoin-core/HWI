from typing import Optional
from ....errors import DeviceCompatibilityError, DeviceCompatibilityErrorType
from ....interfaces import IDeviceConnection
from ....common_utils import assert_condition
from ...config import v3 as config_v3
from ...utils.packet_version import PacketVersion, PacketVersionMap
from ...encoders.packet.packet import encode_packet
from .write_command import write_command
from .can_retry import can_retry


async def send_command(
    connection: IDeviceConnection,
    version: PacketVersion,
    sequence_number: int,
    raw_data: Optional[str] = None,
    proto_data: Optional[str] = None,
    max_tries: int = 5,
    timeout: Optional[int] = None,
) -> None:
    assert_condition(connection, "Invalid connection")
    assert_condition(raw_data or proto_data, "Raw data or proto data is required")
    assert_condition(version, "Invalid version")
    assert_condition(sequence_number, "Invalid sequenceNumber")

    if version != PacketVersionMap.v3:
        raise DeviceCompatibilityError(
            DeviceCompatibilityErrorType.INVALID_SDK_OPERATION
        )

    usable_config = config_v3

    packets_list = encode_packet(
        raw_data=raw_data or "",
        proto_data=proto_data or "",
        version=version,
        sequence_number=sequence_number,
        packet_type=usable_config.commands.PACKET_TYPE.CMD,
    )

    first_error: Optional[Exception] = None

    for packet in packets_list:
        tries = 1
        inner_max_tries = max_tries if max_tries is not None else 5
        first_error = None
        is_success = False

        while tries <= inner_max_tries and not is_success:
            try:
                await write_command(
                    connection=connection,
                    packet=packet,
                    version=version,
                    sequence_number=sequence_number,
                    ack_packet_types=[usable_config.commands.PACKET_TYPE.CMD_ACK],
                    timeout=timeout,
                )
                is_success = True

            except Exception as e:
                if not can_retry(e):
                    tries = inner_max_tries

                if not first_error:
                    first_error = e

            tries += 1

        if not is_success and first_error:
            raise first_error
