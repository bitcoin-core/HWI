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
"""Useful functions"""

from typing import Any, Dict, Optional, List, Tuple
from pathlib import Path
import json
import os
import binascii
import base64
import platform

from ..._base58 import decode_check
from noise.backends.default.keypairs import KeyPair25519

from .bitbox02 import common
from .communication import bitbox_api_protocol


def parse_xpub(xpub: str) -> common.XPub:
    """
    Parse an xpub to a protobuf XPub.
    The version is stripped, so the xpub can be any format (xpub, ypub, etc.).
    """

    decoded = decode_check(xpub)
    decoded = decoded[4:]
    depth, decoded = decoded[:1], decoded[1:]
    parent_fp, decoded = decoded[:4], decoded[4:]
    child_num, decoded = decoded[:4], decoded[4:]
    chain_code, decoded = decoded[:32], decoded[32:]
    pubkey, decoded = decoded[:33], decoded[33:]
    assert len(decoded) == 0
    return common.XPub(
        depth=depth,
        parent_fingerprint=parent_fp,
        child_num=int.from_bytes(child_num, "big"),
        chain_code=chain_code,
        public_key=pubkey,
    )


class UserCache:
    """Data structure to hold keys"""

    def __init__(self, raw_cache: Optional[str] = None):
        if raw_cache is None:
            self.app_static_privkey = None
            self.device_static_pubkeys: List[bytes] = []
            return
        (privkey, pubkeys) = UserCache.deserialize(raw_cache)
        self.app_static_privkey = privkey
        self.device_static_pubkeys = pubkeys

    def serialize(self) -> str:
        """Serialize struct to string"""
        pubkeys = [binascii.hexlify(x).decode("utf-8") for x in self.device_static_pubkeys]
        privkey = None
        if self.app_static_privkey is not None:
            privkey = binascii.hexlify(self.app_static_privkey).decode("utf-8")
        return json.dumps({"device_static_pubkeys": pubkeys, "app_static_privkey": privkey})

    @staticmethod
    def deserialize(raw: str) -> Tuple[Optional[bytes], List[bytes]]:
        """Deserialize content from disk to struct"""
        try:
            data = json.loads(raw)
            privkey = None
            if data["app_static_privkey"] is not None:
                privkey = binascii.unhexlify(data["app_static_privkey"])
            pubkeys = [binascii.unhexlify(x) for x in data["device_static_pubkeys"]]
            return (privkey, pubkeys)
        except json.JSONDecodeError:
            return (None, [])
        except KeyError:
            return (None, [])


class NoiseConfigUserCache(bitbox_api_protocol.BitBoxNoiseConfig):
    """
    A noise config that stores the keys in a file in XDG_CACHE_HOME or ~/.cache.
    Currently intended as a developer help only (currently no macOS/Windows support).
    """

    def __init__(self, appid: str) -> None:
        """
        Args:
            appid: A string that uniqely identifies your application. It will be used as the name
            of the cache directory. Directory separators will create subdirectories, e.g.
            "shift/test1".
        """
        self._cache_file_path = NoiseConfigUserCache._find_cache_file(appid)
        super().__init__()

    @staticmethod
    def _find_cache_file(appid: str) -> Path:
        cachedir_env = os.environ.get("XDG_CACHE_HOME", "")
        if cachedir_env == "":
            homedir = os.environ.get("HOME", "")
            if homedir == "":
                raise RuntimeError("Can't find cache dir")
            cachedir = Path(homedir) / ".cache"
        else:
            cachedir = Path(cachedir_env)
        return cachedir / appid / "bitbox02.dat"

    def _read_cache(self) -> UserCache:
        try:
            with self._cache_file_path.open("r") as fileh:
                return UserCache(fileh.read())
        except FileNotFoundError:
            return UserCache()

    def _write_cache(self, data: UserCache) -> None:
        self._cache_file_path.parent.mkdir(parents=True, exist_ok=True)
        with self._cache_file_path.open("w") as fileh:
            fileh.write(data.serialize())

    def contains_device_static_pubkey(self, pubkey: bytes) -> bool:
        data = self._read_cache()
        if pubkey in data.device_static_pubkeys:
            return True
        return False

    def add_device_static_pubkey(self, pubkey: bytes) -> None:
        if not self.contains_device_static_pubkey(pubkey):
            data = self._read_cache()
            data.device_static_pubkeys.append(pubkey)
            self._write_cache(data)

    def get_app_static_privkey(self) -> Optional[bytes]:
        data = self._read_cache()
        return data.app_static_privkey

    def set_app_static_privkey(self, privkey: bytes) -> None:
        data = self._read_cache()
        data.app_static_privkey = privkey
        self._write_cache(data)


class BitBoxAppNoiseConfig(bitbox_api_protocol.BitBoxNoiseConfig):
    """
    Noise config that reads and stores the noise keys in the same location as the BitBoxApp.
    This allows a third party BitBox02 integration to re-use the pairing with the BitBoxApp.
    """

    _DEVICE_NOISE_STATIC_PUBKEYS = "deviceNoiseStaticPubkeys"
    _APP_NOISE_STATIC_KEYPAIR = "appNoiseStaticKeypair"

    def __init__(self) -> None:
        system = platform.system()
        if system == "Linux":
            folder = Path(
                os.environ.get(
                    "XDG_CONFIG_HOME",
                    # fallback
                    os.path.join(os.environ["HOME"], ".config"),
                )
            )
        elif system == "Darwin":
            folder = Path(os.environ["HOME"]) / "Library" / "Application Support"
        elif system == "Windows":
            folder = Path(os.environ["APPDATA"])
        else:
            raise NotImplementedError("Unknown system: {}".format(system))
        self._filename = folder / "bitbox" / "bitbox02" / "bitbox02.json"

    def _read(self) -> Any:
        try:
            with self._filename.open("r") as fileh:
                return json.load(fileh)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            return {}

    def _write(self, data: Dict[str, object]) -> None:
        self._filename.parent.mkdir(parents=True, exist_ok=True)
        with self._filename.open("w") as fileh:
            json.dump(data, fileh)

    def contains_device_static_pubkey(self, pubkey: bytes) -> bool:
        data = self._read()
        return base64.b64encode(pubkey).decode() in data.get(self._DEVICE_NOISE_STATIC_PUBKEYS, [])

    def add_device_static_pubkey(self, pubkey: bytes) -> None:
        if not self.contains_device_static_pubkey(pubkey):
            data = self._read()
            data.setdefault(self._DEVICE_NOISE_STATIC_PUBKEYS, [])
            data[self._DEVICE_NOISE_STATIC_PUBKEYS].append(base64.b64encode(pubkey).decode())
            self._write(data)

    def get_app_static_privkey(self) -> Optional[bytes]:
        data = self._read()
        if self._APP_NOISE_STATIC_KEYPAIR not in data:
            return None

        return base64.b64decode(data[self._APP_NOISE_STATIC_KEYPAIR]["private"])

    def set_app_static_privkey(self, privkey: bytes) -> None:
        data = self._read()
        pubkey = KeyPair25519.from_private_bytes(privkey).public_bytes
        data[self._APP_NOISE_STATIC_KEYPAIR] = {
            "private": base64.b64encode(privkey).decode(),
            "public": base64.b64encode(pubkey).decode(),
        }
        self._write(data)
