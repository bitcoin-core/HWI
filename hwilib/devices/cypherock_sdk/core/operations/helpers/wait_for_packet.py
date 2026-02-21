import threading
import time
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
    def __init__(self):
        self._result = None
        self._error = None
        self._completed = threading.Event()
        self._cancelled = False
        self._lock = threading.Lock()

    def cancel(self):
        with self._lock:
            self._cancelled = True
            self._completed.set()

    def is_cancelled(self) -> bool:
        with self._lock:
            return self._cancelled

    def set_result(self, result: DecodedPacketData):
        with self._lock:
            if not self._cancelled:
                self._result = result
                self._completed.set()

    def set_error(self, error: Exception):
        with self._lock:
            if not self._cancelled:
                self._error = error
                self._completed.set()

    def result(self, timeout: Optional[float] = None) -> DecodedPacketData:
        """Wait for result synchronously. Returns result or raises error."""
        if self._completed.wait(timeout=timeout):
            with self._lock:
                if self._cancelled:
                    raise DeviceConnectionError(DeviceConnectionErrorType.CONNECTION_CLOSED)
                if self._error:
                    raise self._error
                return self._result
        else:
            raise DeviceCommunicationError(DeviceCommunicationErrorType.READ_TIMEOUT)


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
    timeout_val = (
        ack_timeout if ack_timeout is not None else usable_config.constants.ACK_TIME
    )

    task = CancellableTask()
    is_completed = threading.Event()
    stop_event = threading.Event()

    def recheck_packet():
        """Polling thread that checks for incoming packets"""
        start_time = time.time()
        recheck_interval = usable_config.constants.RECHECK_TIME / 1000

        while not stop_event.is_set() and not is_completed.is_set():
            try:
                # Check timeout
                elapsed = (time.time() - start_time) * 1000
                if elapsed >= timeout_val:
                    if not is_completed.is_set():
                        is_completed.set()
                        if not connection.is_connected():
                            task.set_error(DeviceConnectionError(
                                DeviceConnectionErrorType.CONNECTION_CLOSED
                            ))
                        else:
                            task.set_error(DeviceCommunicationError(
                                DeviceCommunicationErrorType.READ_TIMEOUT
                            ))
                    return

                # Check connection
                if not connection.is_connected():
                    if not is_completed.is_set():
                        is_completed.set()
                        task.set_error(DeviceConnectionError(
                            DeviceConnectionErrorType.CONNECTION_CLOSED
                        ))
                    return

                # Try to receive packet
                raw_packet = connection.receive()
                if not raw_packet:
                    time.sleep(recheck_interval)
                    continue

                # Decode and process packet
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
                            latest_seq_number = connection.get_sequence_number()

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

                # Handle result
                if error or is_success:
                    if not is_completed.is_set():
                        is_completed.set()
                        if error:
                            task.set_error(error)
                        elif received_packet:
                            task.set_result(received_packet)
                    return
                else:
                    time.sleep(recheck_interval)

            except Exception as e:
                if hasattr(e, "code") and e.code in [
                    err.value for err in DeviceConnectionErrorType
                ]:
                    if not is_completed.is_set():
                        is_completed.set()
                        task.set_error(e)
                    return

                logger.error("Error while rechecking packet on `waitForPacket`")
                logger.error(str(e))
                time.sleep(recheck_interval)

    # Start the polling thread
    thread = threading.Thread(target=recheck_packet, daemon=True)
    thread.start()

    # Override cancel to also stop the thread
    original_cancel = task.cancel

    def cancel_with_stop():
        stop_event.set()
        original_cancel()
    task.cancel = cancel_with_stop

    return task
