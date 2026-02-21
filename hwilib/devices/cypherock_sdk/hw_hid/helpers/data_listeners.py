import threading
import time
import uuid
import logging
from typing import Any, Dict, Optional

from ...interfaces import IDevice, PoolData

from .connection import get_available_devices

logger = logging.getLogger(__name__)


class DataListener:
    def __init__(self, params: Dict[str, Any]):
        self.connection = params["connection"]
        self.device: IDevice = params["device"]
        self.on_close_callback = params.get("on_close")
        self.on_error_callback = params.get("on_error")
        self.on_some_device_disconnect_binded = self.on_some_device_disconnect
        self.listening = False
        self.pool: [PoolData] = []

        self.read_thread: Optional[threading.Thread] = None
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self.add_all_listeners()

    def destroy(self):
        self.stop_listening()
        self.remove_all_listeners()

        if self.on_close_callback:
            self.on_close_callback()

    def is_listening(self):
        return self.listening

    def receive(self):
        if self.pool:
            return self.pool.pop(0).get("data")
        return None

    def peek(self):
        return self.pool.copy()

    def stop_read_thread(self):
        if self.read_thread and self.read_thread.is_alive():
            self.read_thread.join(timeout=1.0)
            self.read_thread = None

    def start_read_thread(self):
        if self.read_thread is None or not self.read_thread.is_alive():
            self.read_thread = threading.Thread(
                target=self._run_read_loop, daemon=True
            )
            self.read_thread.start()

    def start_listening(self):
        self.listening = True
        self.start_read_thread()

    def stop_listening(self):
        self.stop_read_thread()
        self.listening = False

    def add_all_listeners(self) -> None:
        if not self._monitor_thread or not self._monitor_thread.is_alive():
            logger.debug("Starting device disconnect monitor thread.")
            self._monitor_thread = threading.Thread(
                target=self._run_device_monitor, daemon=True
            )
            self._monitor_thread.start()

    def remove_all_listeners(self) -> None:
        self._stop_event.set()
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=1.0)
            logger.debug("Device disconnect monitor thread stopped.")

    def _run_read_loop(self):
        while self.listening:
            try:
                data = self._read_data()
                if data:
                    self.on_data(data)
            except Exception as error:
                logger.error("Error while reading data from device")
                logger.error(error)
            time.sleep(0.1)  # Small delay to avoid busy-waiting

    def _read_data(self):
        try:
            return self.connection.read(64)
        except Exception as error:
            # Only call error callback for actual errors, not timeouts/empty reads
            error_str = str(error).lower()
            if "timeout" not in error_str and "read error" not in error_str and self.on_error_callback:
                self.on_error_callback(error)
            return None

    def on_data(self, data):
        if data and len(data) > 0:
            self.pool.append({"id": str(uuid.uuid4()), "data": bytearray(data)})

    def on_close(self):
        self.stop_listening()
        self.remove_all_listeners()

        if self.on_close_callback:
            self.on_close_callback()

    def on_error(self, error: Exception):
        if self.on_error_callback:
            self.on_error_callback(error)

    def _run_device_monitor(self):
        while not self._stop_event.is_set():
            try:
                self._check_device_connection()
            except Exception as e:
                logger.error(f"Error in device monitor: {e}")
            time.sleep(1)

    def _check_device_connection(self):
        try:
            self.on_some_device_disconnect()
        except Exception as e:
            logger.error(f"Error checking device connection: {e}")

    def on_some_device_disconnect(self):
        connected_devices = get_available_devices()

        is_device_connected = any(
            d["path"] == self.device["path"]
            and d["serial"] == self.device["serial"]
            and d["product_id"] == self.device["product_id"]
            and d["vendor_id"] == self.device["vendor_id"]
            for d in connected_devices
        )

        if not is_device_connected:
            self.destroy()
            self.on_close()
