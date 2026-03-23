"""Monkey-patch trezorlib to support OneKey-specific protobuf fields."""

from ..trezorlib import messages as _m
from ..trezorlib import protobuf as _pb
from .messages import OneKeyDeviceType

def _apply() -> None:
    # 1. Expose OneKeyDeviceType on the trezorlib messages module so that
    #    protobuf.py:282 `getattr(messages, field.type)` can resolve the
    #    string "OneKeyDeviceType".
    _m.OneKeyDeviceType = OneKeyDeviceType  # type: ignore[attr-defined]

    # 2. Register field 600 on Features.FIELDS.
    _m.Features.FIELDS[600] = _pb.Field(
        "onekey_device_type", "OneKeyDeviceType", repeated=False, required=False
    )

    # 3. Wrap Features.__init__ so that protobuf.py:416
    #    `msg_type(**msg_dict)` can pass onekey_device_type as a keyword arg.
    _orig_init = _m.Features.__init__

    def _patched_init(self, *args, onekey_device_type=None, **kwargs):  # type: ignore[override]
        _orig_init(self, *args, **kwargs)
        self.onekey_device_type = onekey_device_type

    _m.Features.__init__ = _patched_init  # type: ignore[method-assign]


_apply()
