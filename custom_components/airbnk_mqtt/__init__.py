"""Platform for the Airbnk MQTT-based integration."""
import asyncio
import datetime
import logging
import voluptuous as vol

from homeassistant.config_entries import SOURCE_IMPORT, ConfigEntry
from homeassistant.helpers.typing import HomeAssistantType

from .const import DOMAIN, AIRBNK_DEVICES, CONF_DEVICE_CONFIGS

from .lock_device import AirbnkLockMqttDevice

_LOGGER = logging.getLogger(__name__)

ENTRY_IS_SETUP = "airbnk_entry_is_setup"

PARALLEL_UPDATES = 0

SERVICE_FORCE_UPDATE = "force_update"
SERVICE_PULL_DEVICES = "pull_devices"

SIGNAL_DELETE_ENTITY = "airbnk_delete"
SIGNAL_UPDATE_ENTITY = "airbnk_update"

MIN_TIME_BETWEEN_UPDATES = datetime.timedelta(seconds=15)

COMPONENT_TYPES = ["cover", "sensor"]

CONFIG_SCHEMA = vol.Schema(vol.All({DOMAIN: vol.Schema({})}), extra=vol.ALLOW_EXTRA)


async def async_setup(hass, config):
    """Setup the Airbnk component."""

    if DOMAIN not in config:
        return True

    conf = config.get(DOMAIN)
    if conf is not None:
        hass.async_create_task(
            hass.config_entries.flow.async_init(
                DOMAIN, context={"source": SOURCE_IMPORT}, data=conf
            )
        )

    return True


async def async_setup_entry(hass: HomeAssistantType, entry: ConfigEntry):
    """Establish connection with Airbnk."""

    device_configs = entry.data[CONF_DEVICE_CONFIGS]
    entry.add_update_listener(async_options_updated)
    _LOGGER.debug("DEVICES ARE %s", device_configs)
    lock_devices = {}
    for dev_id, dev_config in device_configs.items():
        lock_devices[dev_id] = AirbnkLockMqttDevice(hass, dev_config, entry.options)
        await lock_devices[dev_id].mqtt_subscribe()
    hass.data[DOMAIN] = {AIRBNK_DEVICES: lock_devices}

    for component in COMPONENT_TYPES:
        hass.async_create_task(
            hass.config_entries.async_forward_entry_setup(entry, component)
        )
    return True


async def async_options_updated(hass, entry):
    """Triggered by config entry options updates."""
    for dev_id, device in hass.data[DOMAIN][AIRBNK_DEVICES].items():
        device.set_options(entry.options)


async def async_unload_entry(hass, config_entry):
    """Unload a config entry."""
    await asyncio.wait(
        [
            hass.config_entries.async_forward_entry_unload(config_entry, component)
            for component in COMPONENT_TYPES
        ]
    )
    hass.data[DOMAIN].pop(config_entry.entry_id)
    if not hass.data[DOMAIN]:
        hass.data.pop(DOMAIN)
    return True


async def airbnk_api_setup(hass, host, key, uuid, password):
    """Create a Airbnk instance only once."""
    return
