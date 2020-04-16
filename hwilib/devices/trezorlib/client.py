# This file is part of the Trezor project.
#
# Copyright (C) 2012-2018 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import logging
import sys
import warnings

from mnemonic import Mnemonic

from . import MINIMUM_FIRMWARE_VERSION, exceptions, messages, tools

if sys.version_info.major < 3:
    raise Exception("Trezorlib does not support Python 2 anymore.")

LOG = logging.getLogger(__name__)

VENDORS = ("bitcointrezor.com", "trezor.io", "keepkey.com")
MAX_PASSPHRASE_LENGTH = 50

DEPRECATION_ERROR = """
Incompatible Trezor library detected.

(Original error: {})
""".strip()

OUTDATED_FIRMWARE_ERROR = """
Your Trezor firmware is out of date. Update it with the following command:
  trezorctl firmware-update
Or visit https://wallet.trezor.io/
""".strip()


def get_buttonrequest_value(code):
    # Converts integer code to its string representation of ButtonRequestType
    return [
        k
        for k in dir(messages.ButtonRequestType)
        if getattr(messages.ButtonRequestType, k) == code
    ][0]

class TrezorClient:
    """Trezor client, a connection to a Trezor device.

    This class allows you to manage connection state, send and receive protobuf
    messages, handle user interactions, and perform some generic tasks
    (send a cancel message, initialize or clear a session, ping the device).

    You have to provide a transport, i.e., a raw connection to the device. You can use
    `trezorlib.transport.get_transport` to find one.

    You have to provide an UI implementation for the three kinds of interaction:
    - button request (notify the user that their interaction is needed)
    - PIN request (on T1, ask the user to input numbers for a PIN matrix)
    - passphrase request (ask the user to enter a passphrase)
    See `trezorlib.ui` for details.

    You can supply a `state` you saved in the previous session. If you do,
    the user might not need to enter their passphrase again.
    """

    def __init__(self, transport, ui=None, state=None):
        LOG.info("creating client instance for device: {}".format(transport.get_path()))
        self.transport = transport
        self.ui = ui
        self.state = state

        if ui is None:
            warnings.warn("UI class not supplied. This will probably crash soon.")

        self.session_counter = 0

    def open(self):
        if self.session_counter == 0:
            self.transport.begin_session()
        self.session_counter += 1

    def close(self):
        if self.session_counter == 1:
            self.transport.end_session()
        self.session_counter -= 1

    def cancel(self):
        self._raw_write(messages.Cancel())

    def call_raw(self, msg):
        __tracebackhide__ = True  # for pytest # pylint: disable=W0612
        self._raw_write(msg)
        return self._raw_read()

    def _raw_write(self, msg):
        __tracebackhide__ = True  # for pytest # pylint: disable=W0612
        self.transport.write(msg)

    def _raw_read(self):
        __tracebackhide__ = True  # for pytest # pylint: disable=W0612
        return self.transport.read()

    def _callback_pin(self, msg):
        try:
            pin = self.ui.get_pin(msg.type)
        except exceptions.Cancelled:
            self.call_raw(messages.Cancel())
            raise

        if not pin.isdigit():
            self.call_raw(messages.Cancel())
            raise ValueError("Non-numeric PIN provided")

        resp = self.call_raw(messages.PinMatrixAck(pin=pin))
        if isinstance(resp, messages.Failure) and resp.code in (
            messages.FailureType.PinInvalid,
            messages.FailureType.PinCancelled,
            messages.FailureType.PinExpected,
        ):
            raise exceptions.PinException(resp.code, resp.message)
        else:
            return resp

    def _callback_passphrase(self, msg):
        available_on_device = self.features.model == 'T'

        def send_passphrase(passphrase=None, on_device=None):
            msg = messages.PassphraseAck(passphrase=passphrase, on_device=on_device)
            resp = self.call_raw(msg)
            if isinstance(resp, messages.Deprecated_PassphraseStateRequest):
                self.session_id = resp._state
                resp = self.call_raw(messages.Deprecated_PassphraseStateAck())
            return resp

        # short-circuit old style entry
        if msg._on_device is True:
            return send_passphrase(None, None)

        if available_on_device:
            return send_passphrase(on_device=True)

        try:
            passphrase = self.ui.get_passphrase()
        except:
            self.call_raw(messages.Cancel())
            raise

        # else process host-entered passphrase
        passphrase = Mnemonic.normalize_string(passphrase)
        if len(passphrase) > MAX_PASSPHRASE_LENGTH:
            self.call_raw(messages.Cancel())
            raise ValueError("Passphrase too long")

        return send_passphrase(passphrase=passphrase)

    def _callback_button(self, msg):
        __tracebackhide__ = True  # for pytest # pylint: disable=W0612
        # do this raw - send ButtonAck first, notify UI later
        self._raw_write(messages.ButtonAck())
        self.ui.button_request(msg.code)
        return self._raw_read()

    @tools.session
    def call(self, msg):
        self.check_firmware_version()
        resp = self.call_raw(msg)
        while True:
            if isinstance(resp, messages.PinMatrixRequest):
                resp = self._callback_pin(resp)
            elif isinstance(resp, messages.PassphraseRequest):
                resp = self._callback_passphrase(resp)
            elif isinstance(resp, messages.ButtonRequest):
                resp = self._callback_button(resp)
            elif isinstance(resp, messages.Failure):
                if resp.code == messages.FailureType.ActionCancelled:
                    raise exceptions.Cancelled
                raise exceptions.TrezorFailure(resp)
            else:
                return resp

    @tools.session
    def init_device(self):
        resp = self.call_raw(messages.GetFeatures())
        # If GetFeatures fails, try initializing and clearing inconsistent state on the device
        if isinstance(resp, messages.Failure):
            resp = self.call_raw(messages.Initialize())
        if not isinstance(resp, messages.Features):
            raise exceptions.TrezorException("Unexpected initial response")
        else:
            # If this is a Trezor One or Keepkey, do Initialize
            if resp.model == '1' or resp.model == 'K1-14AM':
                resp = self.call_raw(messages.Initialize())
                if not isinstance(resp, messages.Features):
                    raise exceptions.TrezorException("Unexpected initial response")
            # For the T, we need to check if a passphrase needs to be entered
            elif resp.model == 'T':
                # Try GetPublicKey. If it fails, we try to send Initialize
                pubkey_resp = self.call_raw(messages.GetPublicKey(address_n=[0x8000002c, 0x80000001, 0x80000000]))
                if isinstance(pubkey_resp, messages.Failure):
                    resp = self.call_raw(messages.Initialize())
                    if not isinstance(resp, messages.Features):
                        raise exceptions.TrezorException("Unexpected initial response")
                elif isinstance(pubkey_resp, messages.PassphraseRequest):
                    self.call_raw(messages.Cancel())
            self.features = resp
        if self.features.vendor not in VENDORS:
            raise RuntimeError("Unsupported device")
            # A side-effect of this is a sanity check for broken protobuf definitions.
            # If the `vendor` field doesn't exist, you probably have a mismatched
            # checkout of trezor-common.
        self.version = (
            self.features.major_version,
            self.features.minor_version,
            self.features.patch_version,
        )
        self.check_firmware_version(warn_only=True)

    def is_outdated(self):
        if self.features.bootloader_mode:
            return False
        model = self.features.model or "1"
        required_version = MINIMUM_FIRMWARE_VERSION[model]
        return self.version < required_version

    def check_firmware_version(self, warn_only=False):
        if self.is_outdated():
            if warn_only:
                warnings.warn(OUTDATED_FIRMWARE_ERROR, stacklevel=2)
            else:
                raise exceptions.OutdatedFirmwareError(OUTDATED_FIRMWARE_ERROR)

    @tools.expect(messages.Success, field="message")
    def ping(
        self,
        msg,
        button_protection=False,
        pin_protection=False,
        passphrase_protection=False,
    ):
        # We would like ping to work on any valid TrezorClient instance, but
        # due to the protection modes, we need to go through self.call, and that will
        # raise an exception if the firmware is too old.
        # So we short-circuit the simplest variant of ping with call_raw.
        if not button_protection and not pin_protection and not passphrase_protection:
            # XXX this should be: `with self:`
            try:
                self.open()
                return self.call_raw(messages.Ping(message=msg))
            finally:
                self.close()

        msg = messages.Ping(
            message=msg,
            button_protection=button_protection,
            pin_protection=pin_protection,
            passphrase_protection=passphrase_protection,
        )
        return self.call(msg)

    def get_device_id(self):
        return self.features.device_id

    @tools.expect(messages.Success, field="message")
    @tools.session
    def clear_session(self):
        return self.call_raw(messages.ClearSession())
