"""What a monitor's data points mean, read from its own product schema.

Data point ids are not stable across models. DPS 208 is the temperature in °F
on the SCD973 family but relative humidity on the SCD860, and the SCD860 has no
DPS 158 brightness at all: its night light brightness is the V of the HSV
colour in DPS 204. `tuya.m.device.get` returns the product schema with every
poll, so entities that depend on such a data point check its code there rather
than guessing from the id or the model.

No Home Assistant imports here, so this is unit-tested on its own.
"""
from __future__ import annotations

import json
import logging

_LOGGER = logging.getLogger(__name__)

CODE_HUMIDITY = "sensor_humidity"
CODE_NIGHTLIGHT_COLOR = "nightlight_color"
# On the SCD860 DPS 201 is a plain on/off lullaby switch, DPS 202 the track
# index ("0"-"9"); the SCD973 family uses 201 for play/pause/next/prev commands
# and 202 for a JSON track id.
CODE_LULLABY_SWITCH = "lullaby_switch"
CODE_LULLABY_SELECT = "lullaby_select"

# HSV as three 4-digit hex numbers: hue 0-360, saturation and value 0-1000.
# The SCD860 also sends a trailing newline (diagnostics on #59).
_HSV_LENGTH = 12
_V_MIN = 10
_V_MAX = 1000
# Warm white, the colour the SCD860 reports out of the box.
DEFAULT_HSV = "007803e803e8"


def dp_codes(device_info: dict | None) -> dict[str, str]:
    """Map data point id to code from the schema in a device.get result."""
    return {dp_id: str(item["code"]) for dp_id, item in _schema_items(device_info).items()}


def _schema_items(device_info: dict | None) -> dict[str, dict]:
    raw = (device_info or {}).get("schema")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            _LOGGER.debug("Unparseable device schema")
            return {}
    if not isinstance(raw, list):
        return {}
    return {
        str(item["id"]): item
        for item in raw
        if isinstance(item, dict) and "id" in item and "code" in item
    }


def dp_enum_range(device_info: dict | None, dp_id: str) -> list[str]:
    """The values an enum data point accepts, per the schema, or []."""
    prop = _schema_items(device_info).get(dp_id, {}).get("property")
    if isinstance(prop, dict) and isinstance(prop.get("range"), list):
        return [str(v) for v in prop["range"]]
    return []


def lullaby_index_label(value: object) -> str:
    """1-based label for an SCD860 track index ("0" -> "1")."""
    try:
        return str(int(str(value)) + 1)
    except ValueError:
        return str(value)


def lullaby_is_switch(device_info: dict | None) -> bool:
    """Whether DPS 201 is the SCD860's on/off lullaby switch rather than play commands."""
    return dp_codes(device_info).get("201") == CODE_LULLABY_SWITCH


def dp_means(device_info: dict | None, dps: dict, dp_id: str, code: str) -> bool:
    """Whether a data point is present and the schema gives it this code."""
    return dp_id in dps and dp_codes(device_info).get(dp_id) == code


def nightlight_brightness(raw: object) -> int | None:
    """Brightness in percent from a nightlight_color value, or None."""
    if not isinstance(raw, str):
        return None
    hsv = raw.strip()
    if len(hsv) != _HSV_LENGTH:
        return None
    try:
        value = int(hsv[8:12], 16)
    except ValueError:
        return None
    return max(1, min(100, round(value / 10)))


def with_nightlight_brightness(raw: object, percent: float) -> str:
    """The nightlight_color value with a new brightness, hue and saturation kept."""
    hsv = raw.strip() if isinstance(raw, str) else ""
    if len(hsv) != _HSV_LENGTH or nightlight_brightness(hsv) is None:
        hsv = DEFAULT_HSV
    value = max(_V_MIN, min(_V_MAX, round(percent * 10)))
    return f"{hsv[:8]}{value:04x}"
