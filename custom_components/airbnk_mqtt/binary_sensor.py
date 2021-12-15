"""Support for Airbnk binary sensors."""
from __future__ import annotations
import logging

from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
)
from homeassistant.const import (
    DEVICE_CLASS_BATTERY,
)

from .const import (
    DOMAIN as AIRBNK_DOMAIN,
    AIRBNK_DEVICES,
    SENSOR_TYPE_BATTERY_LOW,
)

_LOGGER = logging.getLogger(__name__)

SENSOR_ICON = "hass:post-outline"


async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    """Old way of setting up the platform.

    Can only be called when a user accidentally mentions the platform in their
    config. But even in that case it would have been ignored.
    """


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Airbnk sensors based on config_entry."""
    sensors = []
    for dev_id, device in hass.data[AIRBNK_DOMAIN][AIRBNK_DEVICES].items():
        sensor = AirbnkBinarySensor(hass, device, SENSOR_TYPE_BATTERY_LOW)
        sensors.append(sensor)
    async_add_entities(sensors)


class AirbnkBinarySensor(BinarySensorEntity):
    """Representation of a Binary Sensor."""

    def __init__(self, hass, device, monitored_attr: str):
        """Initialize the sensor."""
        self.hass = hass
        self._device = device
        self._monitored_attribute = monitored_attr
        deviceName = self._device._lockConfig["deviceName"]
        self._name = f"{deviceName} Battery Low"

    async def async_added_to_hass(self):
        """Run when this Entity has been added to HA."""
        # Sensors should also register callbacks to HA when their state changes
        self._device.register_callback(self.async_write_ha_state)

    @property
    def available(self):
        """Return if entity is available or not."""
        return self._device.is_available

    @property
    def unique_id(self):
        """Return a unique ID."""
        devID = self._device._lockConfig["sn"]
        return f"{devID}_{self._monitored_attribute}"

    @property
    def name(self):
        """Return the name of the sensor."""
        return self._name

    @property
    def device_info(self):
        """Return a device description for device registry."""
        return self._device.device_info

    @property
    def state(self):
        """Return the state of the sensor."""
        if self._monitored_attribute in self._device._lockData:
            return self._device._lockData[self._monitored_attribute]
        return None

    @property
    def device_class(self):
        """Return the class of this device."""
        return DEVICE_CLASS_BATTERY

    @property
    def icon(self):
        """Return the icon of this device."""
        return None

    async def async_update(self):
        """Retrieve latest state."""
        # _LOGGER.debug("async_update")
