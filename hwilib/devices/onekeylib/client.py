import sys
import threading
import time

from typing import Any, NoReturn, Optional

from .features import is_onekey_features
from .protocol import resolve_profile, resolve_trezor_model
from ..trezorlib import messages
from ..trezorlib.client import TrezorClient as TransportClient, PASSPHRASE_ON_DEVICE
from ..trezorlib.debuglink import TrezorClientDebugLink

ONEKEY_IDLE_AUTO_PRESS_BUTTON_CODES = {
    messages.ButtonRequestType.SignTx,
    messages.ButtonRequestType.ConfirmOutput,
    messages.ButtonRequestType.FeeOverThreshold,
}
ONEKEY_CALLBACK_AUTO_PRESS_BUTTON_CODES = {
    messages.ButtonRequestType.Address,
    messages.ButtonRequestType.PublicKey,
}


class PassphraseUI:
    def __init__(self, passphrase: str) -> None:
        self.passphrase = passphrase
        self.prompt_shown = False
        self.always_prompt = False
        self.return_passphrase = True

    def button_request(self, code: Optional[int]) -> None:
        if not self.prompt_shown:
            print("Please confirm action on your OneKey device", file=sys.stderr)
        if not self.always_prompt:
            self.prompt_shown = True

    def get_pin(self, code: Optional[int] = None) -> NoReturn:
        raise NotImplementedError("get_pin is not needed")

    def disallow_passphrase(self) -> None:
        self.return_passphrase = False

    def get_passphrase(self, available_on_device: bool) -> object:
        if available_on_device:
            return PASSPHRASE_ON_DEVICE
        if self.return_passphrase:
            return self.passphrase
        raise ValueError("Passphrase from Host is not allowed for this device")


class _OneKeyFeatureClientMixin:
    def _refresh_features(self, features: Any) -> None:
        try:
            super()._refresh_features(features)
            return
        except RuntimeError as e:
            if str(e) != "Unsupported device" or not is_onekey_features(features):
                raise

        if not self.model:
            self.model = resolve_trezor_model(features)
            if self.model is None:
                raise RuntimeError("Unsupported Trezor model")

        self.features = features
        self.version = (
            self.features.major_version,
            self.features.minor_version,
            self.features.patch_version,
        )
        self.check_firmware_version(warn_only=True)
        if self.features.session_id is not None:
            self.session_id = self.features.session_id
            self.features.session_id = None


class OneKeyTransportClient(_OneKeyFeatureClientMixin, TransportClient):
    pass


class OneKeyDebugLinkClient(_OneKeyFeatureClientMixin, TrezorClientDebugLink):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._last_wire_activity = time.monotonic()
        self._auto_press_depth = 0
        self._auto_press_stop: Optional[threading.Event] = None
        self._auto_press_thread: Optional[threading.Thread] = None
        super().__init__(*args, **kwargs)

    def _raw_write(self, msg: Any) -> None:
        self._last_wire_activity = time.monotonic()
        return super()._raw_write(msg)

    def _raw_read(self) -> Any:
        resp = super()._raw_read()
        self._last_wire_activity = time.monotonic()
        return resp

    def _supports_idle_auto_press(self) -> bool:
        features = getattr(self, "features", None)
        return features is not None and resolve_profile(features).supports_idle_auto_press

    def _press_yes_when_idle(self) -> None:
        assert self._auto_press_stop is not None
        while not self._auto_press_stop.wait(0.05):
            if time.monotonic() - self._last_wire_activity < 0.15:
                continue
            try:
                self.debug.press_yes()
            except Exception:
                return

    def _press_yes_until_stopped(self, stop_event: threading.Event) -> None:
        stop_event.wait(0.03)
        while not stop_event.is_set():
            try:
                self.debug.press_yes()
            except Exception:
                return
            stop_event.wait(0.05)

    def _raw_read_with_auto_press(self) -> Any:
        stop_event = threading.Event()
        helper = threading.Thread(
            target=self._press_yes_until_stopped,
            args=(stop_event,),
            name="onekey-callback-auto-press",
            daemon=True,
        )
        helper.start()
        try:
            return self._raw_read()
        finally:
            stop_event.set()
            helper.join(timeout=0.2)

    def begin_idle_auto_press(self) -> bool:
        if not self._supports_idle_auto_press():
            return False

        self._auto_press_depth += 1
        if self._auto_press_thread is not None:
            return True

        self._auto_press_stop = threading.Event()
        self._auto_press_thread = threading.Thread(
            target=self._press_yes_when_idle,
            name="onekey-idle-auto-press",
            daemon=True,
        )
        self._auto_press_thread.start()
        return True

    def end_idle_auto_press(self) -> None:
        if self._auto_press_depth == 0:
            return

        self._auto_press_depth -= 1
        if self._auto_press_depth > 0:
            return

        stop_event = self._auto_press_stop
        thread = self._auto_press_thread
        self._auto_press_stop = None
        self._auto_press_thread = None

        if stop_event is not None:
            stop_event.set()
        if thread is not None:
            thread.join(timeout=0.5)

    def _callback_button(self, msg: messages.ButtonRequest) -> Any:
        code = getattr(msg, "code", None)
        if self._auto_press_depth > 0 and code in ONEKEY_IDLE_AUTO_PRESS_BUTTON_CODES:
            self._raw_write(messages.ButtonAck())
            return self._raw_read()
        if self._auto_press_depth > 0 and code in ONEKEY_CALLBACK_AUTO_PRESS_BUTTON_CODES:
            self._raw_write(messages.ButtonAck())
            return self._raw_read_with_auto_press()
        return super()._callback_button(msg)
