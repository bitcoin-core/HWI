from typing import Optional
import asyncio
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


async def wait_for_idle(
    connection: IDeviceConnection,
    version: PacketVersion,
    timeout: Optional[int] = None,
) -> None:
    async def promise_executor():
        try:
            logger.debug("Waiting for device to be idle")
            is_completed = False

            usable_config = config
            timeout_id: Optional[asyncio.Task] = None
            recheck_timeout_id: Optional[asyncio.Task] = None

            def clean_up():
                nonlocal is_completed
                is_completed = True
                if timeout_id:
                    timeout_id.cancel()
                if recheck_timeout_id:
                    recheck_timeout_id.cancel()

            def set_recheck_timeout():
                nonlocal recheck_timeout_id
                if is_completed:
                    return

                if recheck_timeout_id:
                    recheck_timeout_id.cancel()

                recheck_timeout_id = asyncio.create_task(
                    asyncio.sleep(usable_config.constants.IDLE_RECHECK_TIME / 1000)
                )

            async def recheck_if_idle():
                try:
                    if not connection.is_connected():
                        clean_up()
                        raise DeviceConnectionError(
                            DeviceConnectionErrorType.CONNECTION_CLOSED
                        )

                    if is_completed:
                        return

                    status = await get_status(
                        connection=connection,
                        version=version,
                        dont_log=True,
                    )

                    if (
                        status.device_idle_state
                        != DeviceIdleState.DEVICE_IDLE_STATE_USB
                    ):
                        clean_up()
                        return

                    set_recheck_timeout()
                except Exception as error:
                    if hasattr(error, "code") and error.code in [
                        e.value for e in DeviceConnectionErrorType
                    ]:
                        clean_up()
                        raise error

                    logger.error("Error while rechecking if idle")
                    logger.error(error)
                    set_recheck_timeout()

            async def timeout_handler():
                await asyncio.sleep(
                    (
                        timeout
                        if timeout is not None
                        else usable_config.constants.IDLE_TIMEOUT
                    )
                    / 1000
                )
                clean_up()

                if not connection.is_connected():
                    raise DeviceConnectionError(
                        DeviceConnectionErrorType.CONNECTION_CLOSED
                    )
                else:
                    raise DeviceAppError(DeviceAppErrorType.EXECUTING_OTHER_COMMAND)

            timeout_id = asyncio.create_task(timeout_handler())
            set_recheck_timeout()

            while not is_completed:
                if recheck_timeout_id and recheck_timeout_id.done():
                    await recheck_if_idle()
                    if not is_completed:
                        set_recheck_timeout()
                await asyncio.sleep(0.01)

        except Exception as error:
            raise error

    await promise_executor()
