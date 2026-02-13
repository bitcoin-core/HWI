import asyncio
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


async def write_command(
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

    ack_promise = wait_for_packet(
        connection=connection,
        version=version,
        packet_types=ack_packet_types,
        sequence_number=sequence_number,
        ack_timeout=timeout,
    )

    try:
        send_task = asyncio.create_task(connection.send(packet))

        done, pending = await asyncio.wait(
            [send_task, ack_promise.task], return_when=asyncio.FIRST_COMPLETED
        )

        if send_task in done:
            try:
                await send_task
            except Exception:
                ack_promise.cancel()
                if not connection.is_connected():
                    raise DeviceConnectionError(
                        DeviceConnectionErrorType.CONNECTION_CLOSED
                    )
                else:
                    raise DeviceCommunicationError(
                        DeviceCommunicationErrorType.WRITE_ERROR
                    )

        if ack_promise.task in done:
            if ack_promise.is_cancelled():
                raise Exception("Operation cancelled")

            return await ack_promise.result()

        for task in pending:
            if task != ack_promise.task:
                task.cancel()

        return await ack_promise.result()

    except Exception as error:
        ack_promise.cancel()
        raise error
