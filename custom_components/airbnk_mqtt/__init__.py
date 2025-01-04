"""Platform for the Airbnk MQTT-based integration."""
import asyncio
import datetime
import logging
import voluptuous as vol

from homeassistant.config_entries import SOURCE_IMPORT, ConfigEntry
from homeassistant.helpers.typing import HomeAssistantType
from homeassistant.const import CONF_TOKEN, SERVICE_RELOAD

from .airbnk_api import AirbnkApi
from .const import (
    DOMAIN,
    AIRBNK_DEVICES,
    CONF_DEVICE_CONFIGS,
    CONF_VOLTAGE_THRESHOLDS,
    CONF_USERID,
    CONF_DEVICE_MQTT_TYPE,
    CONF_CUSTOM_MQTT,
)
from .tasmota_device import TasmotaMqttLockDevice
from .custom_device import CustomMqttLockDevice

_LOGGER = logging.getLogger(__name__)

ENTRY_IS_SETUP = "airbnk_entry_is_setup"

PARALLEL_UPDATES = 0

SERVICE_FORCE_UPDATE = "force_update"
SERVICE_PULL_DEVICES = "pull_devices"

SIGNAL_DELETE_ENTITY = "airbnk_delete"
SIGNAL_UPDATE_ENTITY = "airbnk_update"

MIN_TIME_BETWEEN_UPDATES = datetime.timedelta(seconds=15)

COMPONENT_TYPES = ["binary_sensor", "cover", "sensor"]

CONFIG_SCHEMA = vol.Schema(vol.All({DOMAIN: vol.Schema({})}), extra=vol.ALLOW_EXTRA)


async def async_setup(hass, config):
    """Setup the Airbnk component."""

    async def _handle_reload(service):
        """Handle reload service call."""
        _LOGGER.debug("Service %s.reload called: reloading integration", DOMAIN)

        current_entries = hass.config_entries.async_entries(DOMAIN)

        # Create tasks for each config entry reload
        reload_tasks = [
            hass.config_entries.async_reload(entry.entry_id)
            for entry in current_entries
        ]

        # Await all tasks concurrently
        await asyncio.gather(*reload_tasks)
        _LOGGER.debug("RELOAD DONE")

    # Register the reload service for admin use
    hass.helpers.service.async_register_admin_service(
        DOMAIN,
        SERVICE_RELOAD,
        _handle_reload,
    )

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


async def async_migrate_entry(hass, config_entry: ConfigEntry):
    """Migrate old entry."""
    _LOGGER.debug("Migrating from version %s", config_entry.version)

    if config_entry.version == 1:

        new_data = {**config_entry.data}
        device_configs = new_data[CONF_DEVICE_CONFIGS]
        for dev_id, dev_config in device_configs.items():
            res_json = await AirbnkApi.getVoltageCfg(
                hass,
                new_data[CONF_USERID],
                new_data[CONF_TOKEN],
                dev_config["deviceType"],
                dev_config["hardwareVersion"],
            )
            if res_json is None:
                _LOGGER.error("Migration from version %s FAILED", config_entry.version)
                return False
            _LOGGER.debug("Retrieved voltage config: %s", res_json)

            dev_config[CONF_VOLTAGE_THRESHOLDS] = []
            for i in range(1, 5):
                dev_config[CONF_VOLTAGE_THRESHOLDS].append(
                    float(res_json["fvoltage" + str(i)])
                )

        config_entry.version = 2
        hass.config_entries.async_update_entry(config_entry, data=new_data)

    _LOGGER.info("Migration to version %s successful", config_entry.version)

    return True


async def async_setup_entry(hass: HomeAssistantType, entry: ConfigEntry):
    """Establish connection with Airbnk."""

    device_configs = entry.data[CONF_DEVICE_CONFIGS]
    entry.add_update_listener(async_options_updated)
    _LOGGER.debug("DEVICES ARE %s", device_configs)

    # Create lock devices and subscribe to MQTT
    lock_devices = {}
    for dev_id, dev_config in device_configs.items():
        if dev_config[CONF_DEVICE_MQTT_TYPE] == CONF_CUSTOM_MQTT:
            lock_devices[dev_id] = CustomMqttLockDevice(hass, dev_config, entry.options)
        else:
            lock_devices[dev_id] = TasmotaMqttLockDevice(
                hass, dev_config, entry.options
            )
        await lock_devices[dev_id].mqtt_subscribe()

    # Store lock devices in hass.data
    hass.data[DOMAIN] = {AIRBNK_DEVICES: lock_devices}

    # Setup components like binary_sensor, cover, etc.
    for component in COMPONENT_TYPES:
        hass.async_create_task(
            hass.config_entries.async_forward_entry_setup(entry, component)
        )
    return True


async def async_options_updated(hass, entry):
    """Triggered by config entry options updates."""
    # Update options for each device
    for dev_id, device in hass.data[DOMAIN][AIRBNK_DEVICES].items():
        device.set_options(entry.options)


async def async_unload_entry(hass, config_entry):
    """Unload a config entry."""
    _LOGGER.debug("Unloading %s %s", config_entry.entry_id, config_entry.data)

    # Create a list of coroutines to be awaited for unloading components
    tasks = [
        hass.config_entries.async_forward_entry_unload(config_entry, component)
        for component in COMPONENT_TYPES
    ]

    # Await all tasks concurrently
    await asyncio.gather(*tasks)

    # Unsubscribe from MQTT for each device
    for dev_id, device in hass.data[DOMAIN][AIRBNK_DEVICES].items():
        _LOGGER.debug("Unsubscribing %s", dev_id)
        await device.mqtt_unsubscribe()

    # Remove device data from hass
    hass.data[DOMAIN].pop(AIRBNK_DEVICES)
    _LOGGER.debug("...done")
    return True


async def airbnk_api_setup(hass, host, key, uuid, password):
    """Create an Airbnk instance only once."""
    return  # Your logic for setting up the Airbnk API
