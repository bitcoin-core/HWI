import asyncio
from typing import List, Optional
from ....errors import (
    DeviceAppError,
    DeviceAppErrorType,
    DeviceConnectionError,
    DeviceConnectionErrorType,
    DeviceCommunicationError,
    DeviceCommunicationErrorType,
    DeviceCompatibilityError,
    DeviceCompatibilityErrorType,
)
from ....interfaces import IDeviceConnection
from ....common_utils import assert_condition
from ...config import v3 as config_v3
from ...utils.packet_version import PacketVersion, PacketVersionMap
from ...encoders.packet.packet import (
    DecodedPacketData,
    decode_packet,
    decode_payload_data,
    ErrorPacketRejectReason,
    RejectReasonToMsgMap,
)
import logging

logger = logging.getLogger(__name__)

class CancellableTask:
    def __init__(self, task: asyncio.Task):
        self.task = task
        self._cancelled = False

    def cancel(self):
        self._cancelled = True
        if not self.task.done():
            self.task.cancel()

    def is_cancelled(self) -> bool:
        return self._cancelled

    async def result(self):
        return await self.task


def wait_for_packet(
    connection: IDeviceConnection,
    sequence_number: int,
    packet_types: List[int],
    version: PacketVersion,
    ack_timeout: Optional[int] = None,
) -> CancellableTask:
    assert_condition(connection, "Invalid connection")
    assert_condition(version, "Invalid version")
    assert_condition(packet_types, "Invalid packetTypes")
    assert_condition(sequence_number, "Invalid sequenceNumber")
    assert_condition(
        len(packet_types) > 0, "packetTypes should contain atleast 1 element"
    )

    if version != PacketVersionMap.v3:
        raise DeviceCompatibilityError(
            DeviceCompatibilityErrorType.INVALID_SDK_OPERATION
        )

    usable_config = config_v3

    async def promise_func() -> DecodedPacketData:
        if not connection.is_connected():
            raise DeviceConnectionError(DeviceConnectionErrorType.CONNECTION_CLOSED)

        is_completed = False
        success = False
        error_result = None
        result_packet = None
        timeout_task = None
        recheck_task = None

        def cleanup():
            nonlocal is_completed, timeout_task, recheck_task
            is_completed = True
            if timeout_task and not timeout_task.done():
                timeout_task.cancel()
            if recheck_task and not recheck_task.done():
                recheck_task.cancel()

        async def recheck_packet():
            nonlocal success, error_result, result_packet
            while not is_completed:
                try:
                    if not connection.is_connected():
                        error_result = DeviceConnectionError(
                            DeviceConnectionErrorType.CONNECTION_CLOSED
                        )
                        cleanup()
                        return

                    if is_completed:
                        return

                    raw_packet = connection.receive()
                    if not raw_packet:
                        await asyncio.sleep(usable_config.constants.RECHECK_TIME / 1000)
                        continue

                    packet_list = decode_packet(raw_packet, version)

                    is_success = False
                    received_packet: Optional[DecodedPacketData] = None
                    error: Optional[Exception] = None

                    for packet in packet_list:
                        if len(packet["error_list"]) == 0:
                            if (
                                packet["packet_type"]
                                == usable_config.commands.PACKET_TYPE.ERROR
                            ):
                                error = DeviceCommunicationError(
                                    DeviceCommunicationErrorType.WRITE_REJECTED
                                )

                                payload_data = decode_payload_data(
                                    packet["payload_data"], version
                                )
                                raw_data = payload_data["raw_data"]

                                reject_status = int(f"0x{raw_data}", 16)
                                latest_seq_number = (
                                    connection.get_sequence_number()
                                )

                                if (
                                    reject_status
                                    == ErrorPacketRejectReason.INVALID_SEQUENCE_NO
                                    and latest_seq_number != sequence_number
                                ):
                                    error = DeviceAppError(
                                        DeviceAppErrorType.PROCESS_ABORTED
                                    )
                                    break

                                inner_reject_reason = RejectReasonToMsgMap.get(
                                    ErrorPacketRejectReason(reject_status)
                                )

                                if inner_reject_reason:
                                    reject_reason = inner_reject_reason
                                else:
                                    reject_reason = f"Unknown reject reason: {raw_data}"

                                error.message = f"The write packet operation was rejected by the device because: {reject_reason}"

                            elif packet["packet_type"] in packet_types:
                                if (
                                    sequence_number == packet["sequence_number"]
                                    or packet["packet_type"]
                                    == usable_config.commands.PACKET_TYPE.STATUS
                                ):
                                    is_success = True
                                    received_packet = packet

                            if error or is_success:
                                break
                        else:
                            pass

                    if error or is_success:
                        if error:
                            error_result = error
                        elif received_packet:
                            success = True
                            result_packet = received_packet
                        cleanup()
                        return result_packet if is_success else None
                    else:
                        await asyncio.sleep(usable_config.constants.RECHECK_TIME / 1000)

                except Exception as error:
                    if hasattr(error, "code") and error.code in [
                        e.value for e in DeviceConnectionErrorType
                    ]:
                        error_result = error
                        cleanup()
                        return

                    logger.error("Error while rechecking packet on `waitForPacket`")
                    logger.error(str(error))
                    await asyncio.sleep(usable_config.constants.RECHECK_TIME / 1000)

        timeout_val = (
            ack_timeout if ack_timeout is not None else usable_config.constants.ACK_TIME
        )
        timeout_task = asyncio.create_task(asyncio.sleep(timeout_val / 1000))
        recheck_task = asyncio.create_task(recheck_packet())

        try:
            done, pending = await asyncio.wait(
                [timeout_task, recheck_task], return_when=asyncio.FIRST_COMPLETED
            )

            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            if success and result_packet:
                return result_packet
            elif error_result:
                raise error_result
            else:
                # If not successful, then it timed out or had an error
                cleanup()
                if not connection.is_connected():
                    raise DeviceConnectionError(
                        DeviceConnectionErrorType.CONNECTION_CLOSED
                    )
                else:
                    raise DeviceCommunicationError(
                        DeviceCommunicationErrorType.READ_TIMEOUT
                    )
        except Exception as e:
            cleanup()
            raise e

    task = asyncio.create_task(promise_func())
    return CancellableTask(task)
