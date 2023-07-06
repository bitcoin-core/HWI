# Copyright 2019 Shift Cryptosecurity AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""BitBox02"""

from abc import ABC, abstractmethod
import os
import enum
import sys
import base64
import binascii
import hashlib
import time
from typing import Callable, Optional, Dict, Tuple, Union, Sequence
from typing_extensions import TypedDict

import ecdsa
from noise.connection import NoiseConnection, Keypair
import semver

from .devices import parse_device_version, DeviceInfo

from .communication import TransportLayer
from .devices import BITBOX02MULTI, BITBOX02BTC

from .generated import hww_pb2 as hww
from .generated import system_pb2 as system


HWW_CMD = 0x80 + 0x40 + 0x01


class HwwRequestCode:
    # New request.
    REQ_NEW = b"\x00"
    # Poll an outstanding request for completion.
    REQ_RETRY = b"\x01"
    # Cancel any outstanding request.
    REQ_CANCEL = b"\x02"
    # INFO api call (used to be OP_INFO api call), graduated to the toplevel framing so it works
    # the same way for all firmware versions.
    REQ_INFO = b"i"


class HwwResponseCode:
    # Request finished, payload is valid.
    RSP_ACK = b"\x00"
    # Request is outstanding, retry later.
    RSP_NOT_READY = b"\x01"
    # Device is busy, request was dropped.
    RSP_BUSY = b"\x02"
    # Bad request.
    RSP_NACK = b"\x03"


ERR_GENERIC = 103
ERR_DUPLICATE_ENTRY = 107
ERR_USER_ABORT = 104

HARDENED = 0x80000000


class AttestationPubkeyInfo(TypedDict):
    # uncompressed secp256k1 pubkey serialization
    pubkey: bytes
    # if not None, a hex-encoded bootloader hashes (of the padded
    # bootloader binary, i.e. the device bootloader area), for which
    # this attestation pubkey is
    accepted_bootloader_hash: Optional[bytes]


ATTESTATION_PUBKEYS: Sequence[AttestationPubkeyInfo] = [
    {
        "pubkey": binascii.unhexlify(
            "04074ff1273b36c24e80fe3d59e0e897a81732d3f8e9cd07e17e9fc06319cd16b"
            "25cf74255674477b3ac9cbac2d12f0dc27a662681fcbc12955b0bccdcbbdcfd01"
        ),
        "accepted_bootloader_hash": None,
    },
    {
        "pubkey": binascii.unhexlify(
            "044c53a84f41fa7301b378bb3c260fc9b2ff1cbea7a78181279a8566797a736f1"
            "2cea25fa2b1c27a844392fe9b37547dc6fbd00a2676b816e7d2d3562be2a0cbbd"
        ),
        "accepted_bootloader_hash": None,
    },
    {
        "pubkey": binascii.unhexlify(
            "04e9c8dc929796aac65af5084eb54dc1ee482d5e0b5c58e2c93f243c5b70b2152"
            "3324bdb78d7395317da165ef1138826c3ca3c91ca95e6f490c340cf5508a4a3ec"
        ),
        "accepted_bootloader_hash": None,
    },
    {
        "pubkey": binascii.unhexlify(
            "04c2fb05889b9dff5a9fb22a59ee1d16bfc2863f0400ddcb69566e2abe8a15fa0"
            "ba1240254ca45aa310d170e724e1310ce5f611cada76c12e3c24a926a390ca4be"
        ),
        "accepted_bootloader_hash": None,
    },
    {
        "pubkey": binascii.unhexlify(
            "04c4e82d6d1b91e7853eba96a871ad31fc62620b826b0b8acf815c03de31b792a"
            "98e05bb34d3b9e0df1040eac485f03ff8bbbf7a857ef1cf2a49a60ac084efb88f"
        ),
        "accepted_bootloader_hash": None,
    },
    {
        "pubkey": binascii.unhexlify(
            "040526f5b8348a8d55e7b1cac043ce98c55bbdb3311b4d1bb2d654281edf8aeb2"
            "1f018fb027a6b08e4ddc62c919e648690722d00c6f54c668c9bd8224a1d82423a"
        ),
        "accepted_bootloader_hash": binascii.unhexlify(
            "e8fa0bd5fc80b86b9f1ea983664df33b27f6f95855d79fb43248ee4c3d3e6be6"
        ),
    },
    {
        "pubkey": binascii.unhexlify(
            "0422491e19766bd96a56e3f2f3926a6c57b89209ff47bd10e523b223ff65ab9af"
            "11c0a5f62c187514f2117ce772de90f9901ee122af78e69bbc4d29eec811be8ec"
        ),
        "accepted_bootloader_hash": None,
    },
    {
        "pubkey": binascii.unhexlify(
            "049f1b7180014b6de60d41f16a3c0a37b20146585e4884960249d30f3cd68c74d"
            "04420d0cedef5719d6b1529b085ecd534fa6c1690be5eb1b3331bc57b5db224dc"
        ),
        "accepted_bootloader_hash": None,
    },
    {
        "pubkey": binascii.unhexlify(
            "04adaa011a4ced11310728abb64f09636267ce0b05782da6d3eeaf987cec7c64f"
            "279ad55327184f9e5b4a1e53089b31bcc65032dad7205325f41ed3d9fdfba1f88"
        ),
        "accepted_bootloader_hash": None,
    },
    {
        "pubkey": binascii.unhexlify(
            "044a70e663d7fe5fe0d4cbbb752883e35222b8d7d7bffdaa8d591995d1252528a"
            "4e9a3e4d5220d485021728b3cdad4fccc681a6ddeea8e2f7c55b4acde8d53573d"
        ),
        "accepted_bootloader_hash": None,
    },
]

ATTESTATION_PUBKEYS_MAP: Dict[bytes, AttestationPubkeyInfo] = {
    hashlib.sha256(val["pubkey"]).digest(): val for val in ATTESTATION_PUBKEYS
}

OP_ATTESTATION = b"a"
OP_UNLOCK = b"u"
OP_I_CAN_HAS_HANDSHAEK = b"h"
OP_HER_COMEZ_TEH_HANDSHAEK = b"H"
OP_I_CAN_HAS_PAIRIN_VERIFICASHUN = b"v"
OP_NOISE_MSG = b"n"

RESPONSE_SUCCESS = b"\x00"
RESPONSE_FAILURE = b"\x01"

MIN_SUPPORTED_BITBOX02_MULTI_FIRMWARE_VERSION = semver.VersionInfo(9, 0, 0)
MIN_SUPPORTED_BITBOX02_BTCONLY_FIRMWARE_VERSION = semver.VersionInfo(9, 0, 0)
MIN_UNSUPPORTED_BITBOX02_MULTI_FIRMWARE_VERSION = semver.VersionInfo(10, 0, 0)
MIN_UNSUPPORTED_BITBOX02_BTCONLY_FIRMWARE_VERSION = semver.VersionInfo(10, 0, 0)


class Platform(enum.Enum):
    """Available hardware platforms"""

    BITBOX02 = "bitbox02"


class BitBox02Edition(enum.Enum):
    """Editions for the BitBox02 platform"""

    MULTI = "multi"
    BTCONLY = "btconly"


class Bitbox02Exception(Exception):
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__()

    def __str__(self) -> str:
        return f"error code: {self.code}, message: {self.message}"


class UserAbortException(Bitbox02Exception):
    pass


class AttestationException(Exception):
    pass


class FirmwareVersionOutdatedException(Exception):
    def __init__(self, version: semver.VersionInfo, required_version: semver.VersionInfo):
        super().__init__(
            "The BitBox02's firmware is not up to date. Device: {}, Required: {}".format(
                version, required_version
            )
        )


class LibraryVersionOutdatedException(Exception):
    def __init__(self, version: semver.VersionInfo):
        super().__init__(
            "The BitBox02's firmware version {} is too new for this app. Update the app".format(
                version
            )
        )


class UnsupportedException(Exception):
    def __init__(self, need_atleast: semver.VersionInfo):
        super().__init__(
            "This feature is supported from firmware version {}. Please upgrade your firmware.".format(
                need_atleast
            )
        )


class BitBoxNoiseConfig:
    """Stores Functions required setup a noise connection"""

    # pylint: disable=no-self-use,unused-argument
    def show_pairing(self, code: str, device_response: Callable[[], bool]) -> bool:
        """
        Returns True if the user confirms the pairing (both device and host).
        Returns False if the user rejects the pairing (either device or host).
        This function must call device_response() to invoke the pairing screen on the device.
        """
        return device_response()

    def attestation_check(self, result: bool) -> None:
        return

    def contains_device_static_pubkey(self, pubkey: bytes) -> bool:
        return False

    def add_device_static_pubkey(self, pubkey: bytes) -> None:
        pass

    def get_app_static_privkey(self) -> Optional[bytes]:
        return None

    def set_app_static_privkey(self, privkey: bytes) -> None:
        pass


class BitBoxProtocol(ABC):
    """
    Class for executing versioned BitBox operations
    (noise message transmissions, unlocks, etc).
    """

    def __init__(self, transport: TransportLayer):
        super().__init__()
        self._transport = transport
        self._noise: NoiseConnection = None

    def close(self) -> None:
        self._transport.close()

    def _raw_query(self, msg: bytes) -> bytes:
        cid = self._transport.generate_cid()
        return self._transport.query(msg, HWW_CMD, cid)

    def query(self, cmd: bytes, msg_data: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulates the given OP_* command and message data into a packet,
        and unpacks the response status code and data.
        """
        response = self._raw_query(cmd + msg_data)
        return response[:1], response[1:]

    @abstractmethod
    def _encode_noise_request(self, encrypted_msg: bytes) -> bytes:
        """Encapsulates an OP_NOISE_MSG message."""

    @abstractmethod
    def _decode_noise_response(self, encrypted_msg: bytes) -> Tuple[bytes, bytes]:
        """De-encapsulate an OP_NOISE_MSG response."""

    @abstractmethod
    def _handshake_query(self, req: bytes) -> Tuple[bytes, bytes]:
        """
        Executes a OP_HER_COMEZ_TEH_HANDSHAEK query with the given
        request data.
        Returns a pair (response status, response data).
        """

    def encrypted_query(self, msg: bytes) -> bytes:
        """
        Sends msg bytes and reads response bytes over an encrypted channel.
        """
        encrypted_msg = self._noise.encrypt(msg)
        encrypted_msg = self._encode_noise_request(encrypted_msg)

        response = self._raw_query(encrypted_msg)
        response_status, response = self._decode_noise_response(response)
        if response_status != RESPONSE_SUCCESS:
            raise Exception("Noise communication failed.")

        result = self._noise.decrypt(response)
        assert isinstance(result, bytes)
        return result

    # pylint: disable=too-many-branches
    def _create_noise_channel(self, noise_config: BitBoxNoiseConfig) -> NoiseConnection:
        if self._raw_query(OP_I_CAN_HAS_HANDSHAEK) != RESPONSE_SUCCESS:
            self.close()
            raise Exception("Couldn't kick off handshake")

        # init noise channel
        noise = NoiseConnection.from_name(b"Noise_XX_25519_ChaChaPoly_SHA256")
        noise.set_as_initiator()
        private_key = noise_config.get_app_static_privkey()
        if private_key is None:
            private_key = os.urandom(32)
            noise_config.set_app_static_privkey(private_key)
        noise.set_keypair_from_private_bytes(Keypair.STATIC, private_key)
        noise.set_prologue(b"Noise_XX_25519_ChaChaPoly_SHA256")
        noise.start_handshake()
        start_handshake_status, start_handshake_reply = self._handshake_query(noise.write_message())
        if start_handshake_status != RESPONSE_SUCCESS:
            self.close()
            raise Exception("Handshake process request failed.")
        noise.read_message(start_handshake_reply)
        remote_static_key = noise.noise_protocol.handshake_state.rs.public_bytes
        assert not noise.handshake_finished
        send_msg = noise.write_message()
        assert noise.handshake_finished
        pairing_code = base64.b32encode(noise.get_handshake_hash()).decode("ascii")
        handshake_finish_status, response = self._handshake_query(send_msg)
        if handshake_finish_status != RESPONSE_SUCCESS:
            self.close()
            raise Exception("Handshake conclusion failed.")

        # Check if we recognize the device's public key
        pairing_verification_required_by_host = True
        if noise_config.contains_device_static_pubkey(remote_static_key):
            pairing_verification_required_by_host = False

        pairing_verification_required_by_device = response == b"\x01"
        if pairing_verification_required_by_host or pairing_verification_required_by_device:

            def get_device_response() -> bool:
                device_response = self._raw_query(OP_I_CAN_HAS_PAIRIN_VERIFICASHUN)
                if device_response == RESPONSE_SUCCESS:
                    return True
                if device_response == RESPONSE_FAILURE:
                    return False
                raise Exception(f"Unexpected pairing response: f{repr(device_response)}")

            client_response_success = noise_config.show_pairing(
                "{} {}\n{} {}".format(
                    pairing_code[:5], pairing_code[5:10], pairing_code[10:15], pairing_code[15:20]
                ),
                get_device_response,
            )
            if not client_response_success:
                self.close()
                raise Exception("pairing rejected by the user")

            noise_config.add_device_static_pubkey(remote_static_key)
        return noise

    def noise_connect(self, noise_config: BitBoxNoiseConfig) -> None:
        self._noise = self._create_noise_channel(noise_config)

    @abstractmethod
    def unlock_query(self) -> None:
        """
        Executes an unlock query.
        Returns the bytes containing the response status.
        """

    @abstractmethod
    def cancel_outstanding_request(self) -> None:
        """
        Aborts/force close the outstanding request on the device.
        """


class BitBoxProtocolV1(BitBoxProtocol):
    """BitBox Protocol from firmware V1.0.0 onwards."""

    def unlock_query(self) -> None:
        raise NotImplementedError("unlock_query is not supported in BitBox protocol V1")

    def _encode_noise_request(self, encrypted_msg: bytes) -> bytes:
        return encrypted_msg

    def _decode_noise_response(self, encrypted_msg: bytes) -> Tuple[bytes, bytes]:
        """
        Until V7 of the protocol, we don't encapsulate OP_NOISE_MSG responses.
        Let's assume that if a response is empty, that means it
        contains an error.
        """
        if len(encrypted_msg) == 0:
            return RESPONSE_FAILURE, b""
        return RESPONSE_SUCCESS, encrypted_msg

    def _handshake_query(self, req: bytes) -> Tuple[bytes, bytes]:
        """
        V1-6 of the BB noise protocol doesn't encapsulate handshake requests, and don't
        send back a status code in the response.
        """
        noise_result = self._raw_query(req)
        return RESPONSE_SUCCESS, noise_result

    def cancel_outstanding_request(self) -> None:
        raise RuntimeError("cancel_outstanding_request should never be called here.")


class BitBoxProtocolV2(BitBoxProtocolV1):
    """BitBox Protocol from firmware V2.0.0 onwards."""

    def unlock_query(self) -> None:
        unlock_data = self._raw_query(OP_UNLOCK)
        if len(unlock_data) != 0:
            raise ValueError("OP_UNLOCK (V2) replied with wrong length.")


class BitBoxProtocolV3(BitBoxProtocolV2):
    """BitBox Protocol from firmware V3.0.0 onwards."""

    def unlock_query(self) -> None:
        unlock_result, unlock_data = self.query(OP_UNLOCK, b"")
        if len(unlock_data) != 0:
            raise ValueError("OP_UNLOCK (V3) replied with wrong length.")
        if unlock_result == RESPONSE_FAILURE:
            self.close()
            raise Exception("Unlock process aborted")


class BitBoxProtocolV4(BitBoxProtocolV3):
    """BitBox Protocol from firmware V4.0.0 onwards."""

    def _encode_noise_request(self, encrypted_msg: bytes) -> bytes:
        return OP_NOISE_MSG + encrypted_msg


class BitBoxProtocolV7(BitBoxProtocolV4):
    """Noise Protocol from firmware V7.0.0 onwards."""

    def __init__(self, transport: TransportLayer):
        super().__init__(transport)
        self.cancel_requested = False

    def _handshake_query(self, req: bytes) -> Tuple[bytes, bytes]:
        return self.query(OP_HER_COMEZ_TEH_HANDSHAEK, req)

    def _decode_noise_response(self, encrypted_msg: bytes) -> Tuple[bytes, bytes]:
        return encrypted_msg[:1], encrypted_msg[1:]

    def _raw_query(self, msg: bytes) -> bytes:
        """
        Starting with v7.0.0, HWW messages are encapsulated
        into an arbitration layer. The device can respond with
        RSP_NOT_READY to indicate that we should poll it later.
        """
        cid = self._transport.generate_cid()
        status = None
        payload: bytes
        while True:
            response = self._transport.query(HwwRequestCode.REQ_NEW + msg, HWW_CMD, cid)
            assert len(response) != 0, "Unexpected response of length 0 from HWW stack."
            status, payload = response[:1], response[1:]
            if status == HwwResponseCode.RSP_BUSY:
                assert (
                    len(payload) == 0
                ), "Unexpected payload of length {} with RSP_BUSY response.".format(len(payload))
                time.sleep(1)
            else:
                # We've successfully initiated our request.
                break

        if status in [HwwResponseCode.RSP_NACK]:
            # We should never receive a NACK unless some internal error occurs.
            raise Exception("Unexpected NACK response from HWW stack.")

        # The message has been sent. If we have a retry, poll the device until we're ready.
        self.cancel_requested = False
        while status == HwwResponseCode.RSP_NOT_READY:
            assert (
                len(payload) == 0
            ), "Unexpected payload of length {} with RSP_NOT_READY response.".format(len(payload))
            time.sleep(0.2)
            to_send = (
                HwwRequestCode.REQ_CANCEL if self.cancel_requested else HwwRequestCode.REQ_RETRY
            )
            response = self._transport.query(to_send, HWW_CMD, cid)
            assert len(response) != 0, "Unexpected response of length 0 from HWW stack."
            status, payload = response[:1], response[1:]
            if status not in [HwwResponseCode.RSP_NOT_READY, HwwResponseCode.RSP_ACK]:
                # We should never receive a NACK unless some internal error occurs.
                raise Exception(
                    "Unexpected response from HWW stack during retry ({}).".format(repr(status))
                )
        return payload

    def cancel_outstanding_request(self) -> None:
        self.cancel_requested = True


class BitBoxCommonAPI:
    """Class to communicate with a BitBox device"""

    # pylint: disable=too-many-public-methods,too-many-arguments
    def __init__(
        self, transport: TransportLayer, device_info: DeviceInfo, noise_config: BitBoxNoiseConfig
    ):
        """
        Can raise LibraryVersionOutdatedException. check_min_version() should be called following
        the instantiation.
        """
        self.debug = False
        serial_number = device_info["serial_number"]

        if device_info["product_string"] == BITBOX02MULTI:
            self.edition = BitBox02Edition.MULTI
        elif device_info["product_string"] == BITBOX02BTC:
            self.edition = BitBox02Edition.BTCONLY

        self.version = parse_device_version(serial_number)
        if self.version is None:
            transport.close()
            raise ValueError(f"Could not parse version from {serial_number}")

        # Delete the prelease part, as it messes with the comparison (e.g. 3.0.0-pre < 3.0.0 is
        # True, but the 3.0.0-pre has already the same API breaking changes like 3.0.0...).
        self.version = semver.VersionInfo(
            self.version.major, self.version.minor, self.version.patch, build=self.version.build
        )

        # raises exceptions if the library is out of date
        self._check_max_version()

        self._bitbox_protocol: BitBoxProtocol
        if self.version >= semver.VersionInfo(7, 0, 0):
            self._bitbox_protocol = BitBoxProtocolV7(transport)
        elif self.version >= semver.VersionInfo(4, 0, 0):
            self._bitbox_protocol = BitBoxProtocolV4(transport)
        elif self.version >= semver.VersionInfo(3, 0, 0):
            self._bitbox_protocol = BitBoxProtocolV3(transport)
        elif self.version >= semver.VersionInfo(2, 0, 0):
            self._bitbox_protocol = BitBoxProtocolV2(transport)
        else:
            self._bitbox_protocol = BitBoxProtocolV1(transport)

        if self.version >= semver.VersionInfo(2, 0, 0):
            noise_config.attestation_check(self._perform_attestation())
            self._bitbox_protocol.unlock_query()

        self._bitbox_protocol.noise_connect(noise_config)

    # pylint: disable=too-many-return-statements
    def _perform_attestation(self) -> bool:
        """Sends a random challenge and verifies that the response can be verified with
        Shift's root attestation pubkeys. Returns True if the verification is successful."""

        challenge = os.urandom(32)
        response_status, response = self._bitbox_protocol.query(OP_ATTESTATION, challenge)
        if response_status != RESPONSE_SUCCESS:
            return False

        # parse data
        bootloader_hash, response = response[:32], response[32:]
        device_pubkey_bytes, response = response[:64], response[64:]
        certificate, response = response[:64], response[64:]
        root_pubkey_identifier, response = response[:32], response[32:]
        challenge_signature, response = response[:64], response[64:]

        # check attestation
        if root_pubkey_identifier not in ATTESTATION_PUBKEYS_MAP:
            # root pubkey could not be identified.
            return False

        root_pubkey_info = ATTESTATION_PUBKEYS_MAP[root_pubkey_identifier]
        root_pubkey_bytes_uncompressed = root_pubkey_info["pubkey"]
        if (
            root_pubkey_info["accepted_bootloader_hash"] is not None
            and root_pubkey_info["accepted_bootloader_hash"] != bootloader_hash
        ):
            return False

        root_pubkey = ecdsa.VerifyingKey.from_string(
            root_pubkey_bytes_uncompressed[1:], ecdsa.curves.SECP256k1
        )

        device_pubkey = ecdsa.VerifyingKey.from_string(device_pubkey_bytes, ecdsa.curves.NIST256p)

        try:
            # Verify certificate
            if not root_pubkey.verify(
                certificate, bootloader_hash + device_pubkey_bytes, hashfunc=hashlib.sha256
            ):
                return False

            # Verify challenge
            if not device_pubkey.verify(challenge_signature, challenge, hashfunc=hashlib.sha256):
                return False
        except ecdsa.BadSignatureError:
            return False
        return True

    def _msg_query(
        self, request: hww.Request, expected_response: Optional[str] = None
    ) -> hww.Response:
        """
        Sends protobuf msg and retrieves protobuf response over an encrypted
        channel.
        """
        # pylint: disable=no-member
        if self.debug:
            print(request)
        response_bytes = self._bitbox_protocol.encrypted_query(request.SerializeToString())
        response = hww.Response()
        response.ParseFromString(response_bytes)
        if response.WhichOneof("response") == "error":
            if response.error.code == ERR_USER_ABORT:
                raise UserAbortException(response.error.code, response.error.message)
            raise Bitbox02Exception(response.error.code, response.error.message)
        if expected_response is not None and response.WhichOneof("response") != expected_response:
            raise Exception(
                "Unexpected response: {}, expected: {}".format(
                    response.WhichOneof("response"), expected_response
                )
            )
        if self.debug:
            print(response)
        return response

    def reboot(
        self, purpose: "system.RebootRequest.Purpose.V" = system.RebootRequest.Purpose.UPGRADE
    ) -> bool:
        """
        Sends the reboot request. If the user confirms the request on the device, the device reboots
        into the bootloader.
        The purpose defines what confirmation message the user gets to see on the device.
        """
        # pylint: disable=no-member
        request = hww.Request()
        request.reboot.CopyFrom(system.RebootRequest(purpose=purpose))
        try:
            self._msg_query(request)
        except OSError:
            # In case of reboot we can't read the response.
            return True
        except Bitbox02Exception:
            return False
        return True

    @staticmethod
    def get_info(transport: TransportLayer) -> Tuple[str, Platform, Union[BitBox02Edition], bool]:
        """
        Returns (version, platform, edition, unlocked).
        This is useful to get the version of the firmware when a usb descriptor is not available
        (via BitBoxBridge, etc.).
        This call does not use a versioned BitBoxProtocol for communication, as the version is not
        available (this call is used to get the version), so it must work for all firmware versions.
        """
        response = transport.query(HwwRequestCode.REQ_INFO, HWW_CMD, transport.generate_cid())

        version_str_len, response = int(response[0]), response[1:]
        version, response = response[:version_str_len], response[version_str_len:]
        version_str = version.rstrip(b"\0").decode("ascii")

        platform_byte, response = response[0], response[1:]
        platform = {0x00: Platform.BITBOX02}[platform_byte]

        edition_byte, response = response[0], response[1:]
        edition: Union[BitBox02Edition]
        if platform == Platform.BITBOX02:
            edition = {0x00: BitBox02Edition.MULTI, 0x01: BitBox02Edition.BTCONLY}[edition_byte]
        else:
            raise Exception("Unknown platform: {}".format(platform))

        unlocked_byte = response[0]
        unlocked = {0x00: False, 0x01: True}[unlocked_byte]
        return (version_str, platform, edition, unlocked)

    def check_min_version(self) -> None:
        """
        Raises FirmwareVersionOutdatedException if the device has an older firmware version than
        required and the minimum required version.
        """
        if self.edition == BitBox02Edition.MULTI:
            if self.version < MIN_SUPPORTED_BITBOX02_MULTI_FIRMWARE_VERSION:
                raise FirmwareVersionOutdatedException(
                    self.version, MIN_SUPPORTED_BITBOX02_MULTI_FIRMWARE_VERSION
                )
        elif self.edition == BitBox02Edition.BTCONLY:
            if self.version < MIN_SUPPORTED_BITBOX02_BTCONLY_FIRMWARE_VERSION:
                raise FirmwareVersionOutdatedException(
                    self.version, MIN_SUPPORTED_BITBOX02_BTCONLY_FIRMWARE_VERSION
                )

    def cancel_outstanding_request(self) -> None:
        self._bitbox_protocol.cancel_outstanding_request()

    def _check_max_version(self) -> None:
        """
        Raises LibraryVersionOutdatedException if the device has an firmware which is too new
        (major version increased).
        """
        if self.edition == BitBox02Edition.MULTI:
            if self.version >= MIN_UNSUPPORTED_BITBOX02_MULTI_FIRMWARE_VERSION:
                raise LibraryVersionOutdatedException(self.version)
        elif self.edition == BitBox02Edition.BTCONLY:
            if self.version >= MIN_UNSUPPORTED_BITBOX02_BTCONLY_FIRMWARE_VERSION:
                raise LibraryVersionOutdatedException(self.version)

    def _require_atleast(self, version: semver.VersionInfo) -> None:
        """
        Raises UnsupportedException if the current firmware version is not at least the required version.
        """
        if self.version < version:
            raise UnsupportedException(version)

    def close(self) -> None:
        self._bitbox_protocol.close()
