"""Number entities for Philips Avent Baby Monitor."""
from __future__ import annotations

from functools import partial

from homeassistant.components.number import NumberEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    DOMAIN,
    DPS_AWAKE_DELAY,
    DPS_BRIGHTNESS,
    DPS_LIGHT_COLOR,
    DPS_LULLABY_VOLUME,
)
from .coordinator import PhilipsAventCoordinator
from .dps_schema import CODE_NIGHTLIGHT_COLOR, dp_means, nightlight_brightness, with_nightlight_brightness
from .entity import add_entities_when_ready, build_device_info, dps_present


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    data = hass.data[DOMAIN][entry.entry_id]
    entities = []
    for cam_id, coordinator in data["coordinators"].items():
        entities.extend([
            AventNightLightBrightness(coordinator, cam_id),
            AventNumber(coordinator, cam_id, DPS_LULLABY_VOLUME, None, "mdi:volume-medium", 1, 100, 1, "%", translation_key="lullaby_volume"),
        ])
        # SenseIQ: delay before the "baby awake" alert fires (seconds).
        add_entities_when_ready(coordinator, async_add_entities, [
            (dps_present(DPS_AWAKE_DELAY), partial(_awake_delay, coordinator, cam_id)),
        ], entry.async_on_unload)
    async_add_entities(entities)


def _awake_delay(coordinator: PhilipsAventCoordinator, cam_id: str) -> list:
    return [
        AventNumber(coordinator, cam_id, DPS_AWAKE_DELAY, None, "mdi:timer-outline", 0, 600, 30, "s", translation_key="awake_alert_delay")
    ]


class AventNumber(CoordinatorEntity, NumberEntity):
    _attr_has_entity_name = True

    def __init__(
        self, coordinator: PhilipsAventCoordinator, cam_id: str,
        dps_id: str, name: str | None, icon: str,
        min_val: float, max_val: float, step: float, unit: str,
        *, translation_key: str | None = None,
    ):
        super().__init__(coordinator)
        self._cam_id = cam_id
        self._dps_id = dps_id
        if translation_key is not None:
            self._attr_translation_key = translation_key
        else:
            self._attr_name = name
        self._attr_icon = icon
        self._attr_native_min_value = min_val
        self._attr_native_max_value = max_val
        self._attr_native_step = step
        self._attr_native_unit_of_measurement = unit
        self._attr_unique_id = f"{cam_id}_{dps_id}"
        self._attr_device_info = build_device_info(coordinator, cam_id)

    @property
    def native_value(self) -> float | None:
        dps = self.coordinator.data
        if dps and self._dps_id in dps:
            return float(dps[self._dps_id])
        return None

    async def async_set_native_value(self, value: float) -> None:
        await self.coordinator.set_dps({self._dps_id: int(value)})


class AventNightLightBrightness(AventNumber):
    """Night light brightness: DPS 158 where the monitor has it, otherwise the V of
    the HSV colour in DPS 204 (SCD860). The unique id stays the DPS 158 one, so
    existing entities keep their history."""

    def __init__(self, coordinator: PhilipsAventCoordinator, cam_id: str):
        super().__init__(
            coordinator, cam_id, DPS_BRIGHTNESS, None, "mdi:brightness-6", 1, 100, 1, "%",
            translation_key="night_light_brightness",
        )

    def _uses_colour(self) -> bool:
        dps = self.coordinator.data or {}
        return DPS_BRIGHTNESS not in dps and dp_means(
            self.coordinator.device_info, dps, DPS_LIGHT_COLOR, CODE_NIGHTLIGHT_COLOR
        )

    @property
    def native_value(self) -> float | None:
        if self._uses_colour():
            value = nightlight_brightness(self.coordinator.data.get(DPS_LIGHT_COLOR))
            return float(value) if value is not None else None
        return super().native_value

    async def async_set_native_value(self, value: float) -> None:
        if self._uses_colour():
            colour = with_nightlight_brightness(self.coordinator.data.get(DPS_LIGHT_COLOR), value)
            await self.coordinator.set_dps({DPS_LIGHT_COLOR: colour})
            return
        await super().async_set_native_value(value)
