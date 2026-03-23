from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..trezorlib import models as trezor_models
from .messages import OneKeyDeviceType


@dataclass(frozen=True)
class OneKeyProfile:
    name: str
    trezor_model: object
    uses_host_pin: bool
    requires_serialized_signatures: bool
    supports_idle_auto_press: bool
    emulator_kind: str


def normalize_model(model: Optional[str]) -> str:
    return (model or "").lower().replace("_", "").replace("-", "")


ONEKEY_DEVICE_TYPE_MODELS = {
    OneKeyDeviceType.CLASSIC: "classic",
    OneKeyDeviceType.CLASSIC1S: "classic1s",
    OneKeyDeviceType.MINI: "mini",
    OneKeyDeviceType.TOUCH: "touch",
    OneKeyDeviceType.TOUCH_PRO: "touchpro",
    OneKeyDeviceType.PRO: "pro",
    OneKeyDeviceType.PURE: "classicpure",
}

_LEGACY_PROFILE = OneKeyProfile(
    name="1",
    trezor_model=trezor_models.T1B1,
    uses_host_pin=True,
    requires_serialized_signatures=True,
    supports_idle_auto_press=True,
    emulator_kind="legacy",
)
_CORE_PROFILE = OneKeyProfile(
    name="pro",
    trezor_model=trezor_models.T2T1,
    uses_host_pin=False,
    requires_serialized_signatures=False,
    supports_idle_auto_press=True,
    emulator_kind="core",
)
_GENERIC_PROFILE = OneKeyProfile(
    name="unknown",
    trezor_model=trezor_models.T1B1,
    uses_host_pin=False,
    requires_serialized_signatures=False,
    supports_idle_auto_press=False,
    emulator_kind="unknown",
)

_PROFILE_BY_NAME: Dict[str, OneKeyProfile] = {
    "1": _LEGACY_PROFILE,
    "classic": OneKeyProfile(
        name="classic",
        trezor_model=trezor_models.T1B1,
        uses_host_pin=True,
        requires_serialized_signatures=True,
        supports_idle_auto_press=True,
        emulator_kind="legacy",
    ),
    "classic1s": OneKeyProfile(
        name="classic1s",
        trezor_model=trezor_models.T1B1,
        uses_host_pin=True,
        requires_serialized_signatures=True,
        supports_idle_auto_press=True,
        emulator_kind="legacy",
    ),
    "classicpure": OneKeyProfile(
        name="classicpure",
        trezor_model=trezor_models.T1B1,
        uses_host_pin=True,
        requires_serialized_signatures=True,
        supports_idle_auto_press=True,
        emulator_kind="legacy",
    ),
    "mini": OneKeyProfile(
        name="mini",
        trezor_model=trezor_models.T1B1,
        uses_host_pin=False,
        requires_serialized_signatures=False,
        supports_idle_auto_press=False,
        emulator_kind="unknown",
    ),
    "touch": OneKeyProfile(
        name="touch",
        trezor_model=trezor_models.T2T1,
        uses_host_pin=False,
        requires_serialized_signatures=False,
        supports_idle_auto_press=False,
        emulator_kind="unknown",
    ),
    "touchpro": OneKeyProfile(
        name="touchpro",
        trezor_model=trezor_models.T2T1,
        uses_host_pin=False,
        requires_serialized_signatures=False,
        supports_idle_auto_press=False,
        emulator_kind="unknown",
    ),
    "pro": _CORE_PROFILE,
}

_PROFILE_ALIASES = {
    "t": "pro",
}


def get_model(features: Any) -> str:
    device_type = getattr(features, "onekey_device_type", None)
    if device_type in ONEKEY_DEVICE_TYPE_MODELS:
        return ONEKEY_DEVICE_TYPE_MODELS[device_type]

    model_name = normalize_model(getattr(features, "model", None))
    return _PROFILE_ALIASES.get(model_name, model_name) or "unknown"


def resolve_profile_name(model_or_features: Any) -> str:
    if hasattr(model_or_features, "model") or hasattr(model_or_features, "onekey_device_type"):
        model_name = get_model(model_or_features)
    else:
        model_name = normalize_model(model_or_features)

    return _PROFILE_ALIASES.get(model_name, model_name)


def resolve_profile(model_or_features: Any) -> OneKeyProfile:
    profile_name = resolve_profile_name(model_or_features)
    if profile_name in _PROFILE_BY_NAME:
        return _PROFILE_BY_NAME[profile_name]

    if hasattr(model_or_features, "model"):
        raw_model = _PROFILE_ALIASES.get(normalize_model(getattr(model_or_features, "model", None)), "")
        if raw_model in _PROFILE_BY_NAME:
            return _PROFILE_BY_NAME[raw_model]

    return _GENERIC_PROFILE


def resolve_trezor_model(features: Any) -> object:
    profile = resolve_profile(features)
    return profile.trezor_model
