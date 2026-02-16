from typing import List, Optional
from ....errors import (
    DeviceCommunicationError,
    DeviceCommunicationErrorType,
    DeviceCompatibilityError,
    DeviceCompatibilityErrorType,
    DeviceConnectionError,
    DeviceConnectionErrorType,
)
from ....interfaces import IDeviceConnection
from ....common_utils import assert_condition
from ...utils.packet_version import PacketVersion, PacketVersionMap
from ...encoders.packet.packet import DecodedPacketData
from .wait_for_packet import wait_for_packet


def write_command(
    connection: IDeviceConnection,
    packet: bytes,
    version: PacketVersion,
    sequence_number: int,
    ack_packet_types: List[int],
    timeout: Optional[int] = None,
) -> DecodedPacketData:
    assert_condition(connection, "Invalid connection")
    assert_condition(packet, "Invalid packet")
    assert_condition(version, "Invalid version")
    assert_condition(ack_packet_types, "Invalid ackPacketTypes")
    assert_condition(sequence_number, "Invalid sequenceNumber")

    assert_condition(
        len(ack_packet_types) > 0, "ackPacketTypes should contain atleast 1 element"
    )
    assert_condition(len(packet) > 0, "packet cannot be empty")

    if version != PacketVersionMap.v3:
        raise DeviceCompatibilityError(
            DeviceCompatibilityErrorType.INVALID_SDK_OPERATION
        )

    if not connection.is_connected():
        raise DeviceConnectionError(DeviceConnectionErrorType.CONNECTION_CLOSED)

    # Start waiting for acknowledgment packet (non-blocking, runs in background thread)
    ack_promise = wait_for_packet(
        connection=connection,
        version=version,
        packet_types=ack_packet_types,
        sequence_number=sequence_number,
        ack_timeout=timeout,
    )

    try:
        # Send the packet synchronously (blocking call)
        try:
            connection.send(packet)
        except Exception as send_error:
            # If send fails, cancel the ack wait and raise error
            ack_promise.cancel()
            if not connection.is_connected():
                raise DeviceConnectionError(
                    DeviceConnectionErrorType.CONNECTION_CLOSED
                )
            else:
                raise DeviceCommunicationError(
                    DeviceCommunicationErrorType.WRITE_ERROR
                ) from send_error

        # Wait for acknowledgment (blocking call, will return result or raise error)
        try:
            return ack_promise.result()
        except Exception as ack_error:
            # If ack wait was cancelled, check why
            if ack_promise.is_cancelled():
                raise Exception("Operation cancelled") from ack_error
            raise

    except Exception as error:
        # Ensure we cancel the ack wait if something goes wrong
        ack_promise.cancel()
        raise error