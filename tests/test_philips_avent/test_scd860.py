"""SCD860 data points (#59): sound alerts, humidity and HSV night light brightness.

The values come from the diagnostics and log attached to #59 and from a second
SCD860 (productId hduoyookoe1b3in0, firmware 200.183.181.12).
"""
import json

from const import DPS_DECIBEL_EVENT, DPS_HUMIDITY, DPS_LIGHT_COLOR, DPS_TEMPERATURE_F
from dps_schema import (
    CODE_HUMIDITY,
    CODE_NIGHTLIGHT_COLOR,
    DEFAULT_HSV,
    dp_codes,
    dp_enum_range,
    dp_means,
    lullaby_index_label,
    lullaby_is_switch,
    nightlight_brightness,
    with_nightlight_brightness,
)
from events import is_decibel_event

# The SCD860's product schema, as tuya.m.device.get returns it (descriptions dropped).
SCD860_SCHEMA = json.dumps([
    {"id": 101, "code": "basic_indicator", "mode": "rw", "type": "obj", "property": {"type": "bool"}},
    {"id": 138, "code": "bulb_switch", "mode": "rw", "type": "obj", "property": {"type": "bool"}},
    {"id": 139, "code": "decibel_switch", "mode": "rw", "type": "obj", "property": {"type": "bool"}},
    {"id": 140, "code": "decibel_sensitivity", "mode": "rw", "type": "obj", "property": {"range": ["0", "1"], "type": "enum"}},
    {"id": 141, "code": "decibel_upload", "mode": "ro", "type": "obj", "property": {"type": "string", "maxlen": 255}},
    {"id": 201, "code": "lullaby_switch", "mode": "rw", "type": "obj", "property": {"type": "bool"}},
    {"id": 202, "code": "lullaby_select", "mode": "rw", "type": "obj",
     "property": {"range": ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"], "type": "enum"}},
    {"id": 203, "code": "lullaby_playmode", "mode": "rw", "type": "obj", "property": {"range": ["0", "1", "2"], "type": "enum"}},
    {"id": 204, "code": "nightlight_color", "mode": "rw", "type": "obj", "property": {"type": "string", "maxlen": 255}},
    {"id": 205, "code": "power_off_alarm", "mode": "ro", "type": "raw", "property": {"type": "raw", "maxlen": 128}},
    {"id": 206, "code": "OTA_message", "mode": "ro", "type": "raw", "property": {"type": "raw", "maxlen": 128}},
    {"id": 207, "code": "sensor_temperature", "mode": "ro", "type": "obj",
     "property": {"unit": "C", "min": 0, "max": 5000, "scale": 0, "step": 1, "type": "value"}},
    {"id": 208, "code": "sensor_humidity", "mode": "ro", "type": "obj",
     "property": {"unit": "%", "min": 0, "max": 10000, "scale": 0, "step": 1, "type": "value"}},
    {"id": 209, "code": "basic_device_volume", "mode": "rw", "type": "obj",
     "property": {"unit": "", "min": 1, "max": 100, "scale": 0, "step": 1, "type": "value"}},
])
SCD860_INFO = {"productId": "hduoyookoe1b3in0", "schema": SCD860_SCHEMA}
# The SCD973 family reports °F on the same id.
SCD973_INFO = {"schema": json.dumps([
    {"id": 158, "code": "floodlight_lightness"},
    {"id": 201, "code": "play_control", "property": {"range": ["play", "pause", "stop", "next", "prev"], "type": "enum"}},
    {"id": 208, "code": "temp_report"},
])}

SCD860_DPS = {
    "101": False, "138": False, "139": True, "140": "1", "141": "1", "201": False, "202": "0", "203": "0",
    "204": "0134027a03e1\n", "207": 2668, "208": 6016, "209": 71,
}


class TestSoundEvent:
    def test_scd860_push(self):
        # The LAN pushes on #59: {'141': '1'} once per alert.
        assert is_decibel_event("1")

    def test_scd973_push(self):
        assert is_decibel_event("decibel_upload")

    def test_not_events(self):
        for value in ("", "0", None, 1, True, "motion_detection"):
            assert not is_decibel_event(value), value

    def test_key(self):
        assert DPS_DECIBEL_EVENT == "141"


class TestSchema:
    def test_codes_from_string_schema(self):
        codes = dp_codes(SCD860_INFO)
        assert codes["208"] == CODE_HUMIDITY
        assert codes["204"] == CODE_NIGHTLIGHT_COLOR

    def test_codes_from_list_schema(self):
        assert dp_codes({"schema": [{"id": 208, "code": "sensor_humidity"}]}) == {"208": "sensor_humidity"}

    def test_missing_or_broken_schema(self):
        assert dp_codes(None) == {}
        assert dp_codes({}) == {}
        assert dp_codes({"schema": "not json"}) == {}
        assert dp_codes({"schema": [{"id": 1}, "x"]}) == {}

    def test_humidity_only_where_the_schema_says_so(self):
        assert DPS_HUMIDITY == DPS_TEMPERATURE_F == "208"
        assert dp_means(SCD860_INFO, SCD860_DPS, DPS_HUMIDITY, CODE_HUMIDITY)
        assert not dp_means(SCD973_INFO, {"208": 7520}, DPS_HUMIDITY, CODE_HUMIDITY)
        assert not dp_means(SCD860_INFO, {}, DPS_HUMIDITY, CODE_HUMIDITY)

    def test_humidity_scale(self):
        # 6150 -> 6016 on #59 was humidity drifting, not a sound alert.
        assert SCD860_DPS[DPS_HUMIDITY] / 100.0 == 60.16


class TestNightLightColour:
    def test_brightness_with_trailing_newline(self):
        # "0134027a03e1\n" from #59: V = 0x3e1 = 993 -> 99 %.
        assert nightlight_brightness(SCD860_DPS[DPS_LIGHT_COLOR]) == 99

    def test_brightness_bounds(self):
        assert nightlight_brightness("007803e803e8") == 100
        assert nightlight_brightness("007803e8000a") == 1
        assert nightlight_brightness("007803e80000") == 1

    def test_unparseable(self):
        for value in (None, "", "short", "007803e8zzzz", 42):
            assert nightlight_brightness(value) is None, value

    def test_set_keeps_hue_and_saturation(self):
        assert with_nightlight_brightness("0134027a03e1\n", 50) == "0134027a01f4"

    def test_set_clamps(self):
        assert with_nightlight_brightness("007803e803e8", 0).endswith("000a")
        assert with_nightlight_brightness("007803e803e8", 250).endswith("03e8")

    def test_set_without_a_usable_colour_uses_warm_white(self):
        assert with_nightlight_brightness(None, 100) == DEFAULT_HSV
        assert with_nightlight_brightness("garbage", 100) == DEFAULT_HSV

    def test_round_trip(self):
        for pct in (1, 10, 33, 50, 99, 100):
            assert nightlight_brightness(with_nightlight_brightness("0134027a03e1", pct)) == pct


class TestLullabyProfile:
    def test_scd860_has_an_on_off_switch(self):
        assert lullaby_is_switch(SCD860_INFO)

    def test_scd973_keeps_play_commands(self):
        assert not lullaby_is_switch(SCD973_INFO)
        assert not lullaby_is_switch(None)

    def test_track_range_from_schema(self):
        assert dp_enum_range(SCD860_INFO, "202") == [str(i) for i in range(10)]
        assert dp_enum_range(SCD860_INFO, "201") == []
        assert dp_enum_range(None, "202") == []

    def test_track_labels_are_one_based(self):
        assert [lullaby_index_label(v) for v in ("0", "9")] == ["1", "10"]
        assert lullaby_index_label("x") == "x"
