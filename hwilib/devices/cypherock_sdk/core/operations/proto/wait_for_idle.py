from typing import Optional
import time
import threading
from ....interfaces import IDeviceConnection
from ....errors import (
    DeviceConnectionError,
    DeviceConnectionErrorType,
    DeviceAppError,
    DeviceAppErrorType,
)
from ...encoders.proto.generated.core_pb2 import DeviceIdleState
from ...utils.packet_version import PacketVersion
from ...config import v3 as config
from .get_status import get_status
import logging

logger = logging.getLogger(__name__)


def wait_for_idle(
    connection: IDeviceConnection,
    version: PacketVersion,
    timeout: Optional[int] = None,
) -> None:
    logger.debug("Waiting for device to be idle")
    
    usable_config = config
    is_completed = threading.Event()
    stop_event = threading.Event()
    error_to_raise = [None]  # Use list to allow modification from nested function
    
    timeout_val = (
        timeout
        if timeout is not None
        else usable_config.constants.IDLE_TIMEOUT
    ) / 1000  # Convert to seconds
    
    recheck_interval = usable_config.constants.IDLE_RECHECK_TIME / 1000  # Convert to seconds
    
    def check_if_idle():
        """Check if device is idle and handle completion/errors"""
        try:
            if not connection.is_connected():
                is_completed.set()
                error_to_raise[0] = DeviceConnectionError(
                    DeviceConnectionErrorType.CONNECTION_CLOSED
                )
                return
            
            if is_completed.is_set():
                return
            
            # Get device status (synchronous call)
            status = get_status(
                connection=connection,
                version=version,
                dont_log=True,
            )
            
            # Check if device is in USB idle state
            if status.device_idle_state != DeviceIdleState.DEVICE_IDLE_STATE_USB:
                # Device is not idle, we're done waiting
                is_completed.set()
                return
            
            # Device is idle, continue waiting (will check again after interval)
            
        except Exception as error:
            if hasattr(error, "code") and error.code in [
                e.value for e in DeviceConnectionErrorType
            ]:
                is_completed.set()
                error_to_raise[0] = error
                return
            
            logger.error("Error while rechecking if idle")
            logger.error(error)
            # Continue polling despite error
    
    def timeout_handler():
        """Timeout thread that raises error if timeout is reached"""
        time.sleep(timeout_val)
        
        if not is_completed.is_set():
            is_completed.set()
            stop_event.set()
            
            if not connection.is_connected():
                error_to_raise[0] = DeviceConnectionError(
                    DeviceConnectionErrorType.CONNECTION_CLOSED
                )
            else:
                error_to_raise[0] = DeviceAppError(DeviceAppErrorType.EXECUTING_OTHER_COMMAND)
    
    # Start timeout thread
    timeout_thread = threading.Thread(target=timeout_handler, daemon=True)
    timeout_thread.start()
    
    # Main polling loop
    start_time = time.time()
    
    try:
        while not is_completed.is_set() and not stop_event.is_set():
            # Check connection
            if not connection.is_connected():
                is_completed.set()
                error_to_raise[0] = DeviceConnectionError(
                    DeviceConnectionErrorType.CONNECTION_CLOSED
                )
                break
            
            # Check if idle
            check_if_idle()
            
            if is_completed.is_set():
                break
            
            # Sleep before next check
            time.sleep(recheck_interval)
            
            # Also check elapsed time as backup (in case timeout thread has issues)
            elapsed = time.time() - start_time
            if elapsed >= timeout_val:
                is_completed.set()
                stop_event.set()
                if not connection.is_connected():
                    error_to_raise[0] = DeviceConnectionError(
                        DeviceConnectionErrorType.CONNECTION_CLOSED
                    )
                else:
                    error_to_raise[0] = DeviceAppError(DeviceAppErrorType.EXECUTING_OTHER_COMMAND)
                break
        
        # If there's an error to raise, raise it
        if error_to_raise[0]:
            raise error_to_raise[0]
            
    except Exception as error:
        is_completed.set()
        stop_event.set()
        raise error