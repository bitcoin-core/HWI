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

"""
Common interfaces to be used for communication with BitBox devices.
"""

from typing_extensions import Protocol


class TransportLayer(Protocol):
    """
    Abstraction for the transport layer used for transmitting U2F messages.
    This class encapsulates packets on a given physical link capable of
    transmitting byte strings.
    """

    # pylint: disable=unused-argument,no-self-use
    def write(self, data: bytes, endpoint: int, cid: int) -> None:
        """Sends a frame of data to the specified endpoint"""

    def read(self, endpoint: int, cid: int) -> bytes:
        ...

    def query(self, data: bytes, endpoint: int, cid: int) -> bytes:
        self.write(data, endpoint, cid)
        return self.read(endpoint, cid)

    def generate_cid(self) -> int:
        ...

    def close(self) -> None:
        ...


class PhysicalLayer(Protocol):
    # pylint: disable=unused-argument,no-self-use
    def write(self, data: bytes) -> None:
        ...

    def read(self, size: int, timeout_ms: int) -> bytes:
        ...

    def close(self) -> None:
        ...
