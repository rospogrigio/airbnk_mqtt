"""Constants for Airbnk MQTT integration."""

from homeassistant.components.sensor import SensorDeviceClass
from homeassistant.const import (
    CONF_DEVICE_CLASS,
    CONF_TOKEN,
    CONF_NAME,
    CONF_TYPE,
    CONF_UNIT_OF_MEASUREMENT,
    PERCENTAGE,
    UnitOfElectricPotential,
    UnitOfTime,
    SIGNAL_STRENGTH_DECIBELS,
)

DOMAIN = "airbnk_mqtt"

CONF_USERID = "userId"
CONF_TOKENSET = CONF_TOKEN + "set"
CONF_UUID = "uuid"
CONF_DEVICE_CONFIGS = "device_configs"
CONF_LOCKSTATUS = "lockStatus"
CONF_MQTT_TOPIC = "mqtt_topic"
CONF_MAC_ADDRESS = "mac_address"
CONF_VOLTAGE_THRESHOLDS = "voltage_thresholds"
CONF_RETRIES_NUM = "retries_num"

CONF_DEVICE_MQTT_TYPE = "device_mqtt_type"
CONF_CUSTOM_MQTT = "Custom MQTT"
CONF_TASMOTA_MQTT = "Tasmota MQTT"
CONF_MQTT_TYPES = [CONF_CUSTOM_MQTT, CONF_TASMOTA_MQTT]

AIRBNK_DATA = "airbnk_data"
AIRBNK_API = "airbnk_api"
AIRBNK_DEVICES = "airbnk_devices"
AIRBNK_DISCOVERY_NEW = "airbnk_discovery_new_{}"
DEFAULT_RETRIES_NUM = 10

TIMEOUT = 60

LOCK_STATE_LOCKED = 0
LOCK_STATE_UNLOCKED = 1
LOCK_STATE_JAMMED = 2
LOCK_STATE_OPERATING = 3
LOCK_STATE_FAILED = 4

LOCK_STATE_STRINGS = {
    LOCK_STATE_LOCKED: "Locked",
    LOCK_STATE_UNLOCKED: "Unlocked",
    LOCK_STATE_JAMMED: "Jammed",
    LOCK_STATE_OPERATING: "Operating",
    LOCK_STATE_FAILED: "Failed",
}

SENSOR_TYPE_STATE = "state"
SENSOR_TYPE_BATTERY = "battery"
SENSOR_TYPE_VOLTAGE = "voltage"
SENSOR_TYPE_LAST_ADVERT = "last_advert"
SENSOR_TYPE_LOCK_EVENTS = "lock_events"
SENSOR_TYPE_SIGNAL_STRENGTH = "signal_strength"

SENSOR_TYPE_BATTERY_LOW = "battery_low"

SENSOR_TYPES = {
    SENSOR_TYPE_STATE: {
        CONF_NAME: "Status",
        CONF_TYPE: SENSOR_TYPE_STATE,
    },
    SENSOR_TYPE_BATTERY: {
        CONF_NAME: "Battery",
        CONF_TYPE: SENSOR_TYPE_BATTERY,
        CONF_DEVICE_CLASS: SensorDeviceClass.BATTERY,
        CONF_UNIT_OF_MEASUREMENT: PERCENTAGE,
    },
    SENSOR_TYPE_VOLTAGE: {
        CONF_NAME: "Battery voltage",
        CONF_TYPE: SENSOR_TYPE_VOLTAGE,
        CONF_DEVICE_CLASS: SensorDeviceClass.VOLTAGE,
        CONF_UNIT_OF_MEASUREMENT: UnitOfElectricPotential.VOLT,
    },
    SENSOR_TYPE_LAST_ADVERT: {
        CONF_NAME: "Time from last advert",
        CONF_TYPE: SENSOR_TYPE_LAST_ADVERT,
        CONF_UNIT_OF_MEASUREMENT: UnitOfTime.SECONDS,
    },
    SENSOR_TYPE_SIGNAL_STRENGTH: {
        CONF_NAME: "Signal strength",
        CONF_TYPE: SENSOR_TYPE_SIGNAL_STRENGTH,
        CONF_DEVICE_CLASS: SensorDeviceClass.SIGNAL_STRENGTH,
        CONF_UNIT_OF_MEASUREMENT: SIGNAL_STRENGTH_DECIBELS,
    },
    SENSOR_TYPE_LOCK_EVENTS: {
        CONF_NAME: "Lock events counter",
        CONF_TYPE: SENSOR_TYPE_LOCK_EVENTS,
    },
}