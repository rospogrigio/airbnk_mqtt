"""Config flow for the Airbnk platform."""
import logging
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_EMAIL, CONF_CODE, CONF_TOKEN
from homeassistant.core import callback

from .airbnk_api import AirbnkApi
from .const import (
    DOMAIN,
    CONF_USERID,
    CONF_MQTT_TOPIC,
    CONF_MAC_ADDRESS,
    CONF_DEVICE_CONFIGS,
    CONF_VOLTAGE_THRESHOLDS,
    CONF_RETRIES_NUM,
    DEFAULT_RETRIES_NUM,
)

_LOGGER = logging.getLogger(__name__)

SKIP_DEVICE = "skip_device"

STEP1_SCHEMA = vol.Schema({vol.Required(CONF_EMAIL): str})

STEP2_SCHEMA = vol.Schema({vol.Required(CONF_EMAIL): str, vol.Required(CONF_CODE): str})

STEP3_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_MAC_ADDRESS): str,
        vol.Required(CONF_MQTT_TOPIC): str,
        vol.Required(SKIP_DEVICE, default=False): bool,
    }
)


def schema_defaults(schema, dps_list=None, **defaults):
    """Create a new schema with default values filled in."""
    copy = schema.extend({})
    for field, field_type in copy.schema.items():
        if field.schema in defaults:
            field.default = vol.default_factory(defaults[field])
    return copy


@config_entries.HANDLERS.register(DOMAIN)
class FlowHandler(config_entries.ConfigFlow):
    """Handle a config flow."""

    VERSION = 2
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_POLL

    def __init__(self):
        """Initialize the Airbnk config flow."""
        self.host = None
        self.entry_data = {}
        self.entry_data[CONF_DEVICE_CONFIGS] = {}
        self.device_configs = {}
        self.device_index = 0

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler."""
        return AirbnkMqttOptionsFlowHandler(config_entry)

    async def _create_entry(self):
        """Register new entry."""
        # if not self.unique_id:
        #    await self.async_set_unique_id(password)
        # self._abort_if_unique_id_configured()
        if self._async_current_entries():
            return self.async_abort(reason="already_configured")

        await self.async_set_unique_id("Airbnk_" + self.entry_data[CONF_USERID])

        return self.async_create_entry(
            title="Airbnk",
            data={
                CONF_EMAIL: self.entry_data[CONF_EMAIL],
                CONF_TOKEN: self.entry_data[CONF_TOKEN],
                CONF_USERID: self.entry_data[CONF_USERID],
                CONF_DEVICE_CONFIGS: self.entry_data[CONF_DEVICE_CONFIGS],
            },
        )

    async def async_step_init(self, user_input=None):
        """User initiated config flow."""
        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=STEP1_SCHEMA)
        return await self.async_step_verify(user_input)

    async def async_step_user(self, user_input=None):
        """User initiated config flow."""
        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=STEP1_SCHEMA)
        return await self.async_step_verify(user_input)

    async def async_step_verify(self, user_input=None):
        """Config flow: second step."""
        if user_input.get(CONF_CODE) is None:
            email = user_input.get(CONF_EMAIL)
            res = await AirbnkApi.requestVerificationCode(self.hass, email)
            if res is False:
                return self.async_abort(reason="code_request_failed")

            defaults = {}
            defaults.update(user_input or {})
            return self.async_show_form(
                step_id="verify", data_schema=schema_defaults(STEP2_SCHEMA, **defaults)
            )
        return await self.async_get_device_configs(
            user_input.get(CONF_EMAIL), user_input.get(CONF_CODE)
        )

    async def async_get_device_configs(self, email, code):
        """Create device."""
        res_json = await AirbnkApi.retrieveAccessToken(self.hass, email, code)

        if res_json is None:
            return self.async_abort(reason="token_retrieval_failed")
        _LOGGER.info("Token retrieval data: %s", res_json)

        self.entry_data[CONF_EMAIL] = res_json["data"][CONF_EMAIL]
        self.entry_data[CONF_USERID] = res_json["data"][CONF_USERID]
        self.entry_data[CONF_TOKEN] = res_json["data"][CONF_TOKEN]
        _LOGGER.debug(
            "Done!: %s %s %s",
            self.entry_data[CONF_USERID],
            email,
            self.entry_data[CONF_TOKEN],
        )

        self.device_configs = await AirbnkApi.getCloudDevices(
            self.hass, self.entry_data[CONF_USERID], self.entry_data[CONF_TOKEN]
        )
        if len(self.device_configs) == 0:
            return await self._create_entry()
        return await self.async_step_configure_device()

    async def async_step_configure_device(self, user_input=None):
        # Config flow: third step.
        config_key = list(self.device_configs.keys())[self.device_index]
        _LOGGER.debug("Configuring %s", config_key)

        if user_input is not None:
            return await self.async_step_messagebox(user_input)

        dev_config = self.device_configs[config_key]
        defaults = {}
        defaults.update(user_input or {})
        return self.async_show_form(
            step_id="configure_device",
            data_schema=schema_defaults(STEP3_SCHEMA, **defaults),
            errors={},
            description_placeholders={
                "model": dev_config["deviceType"],
                "sn": dev_config["sn"],
            },
        )

    async def async_step_messagebox(self, user_input=None):
        # Config flow: third step.
        config_key = list(self.device_configs.keys())[self.device_index]
        _LOGGER.debug("messagebox for device %s", config_key)

        if CONF_MAC_ADDRESS in user_input:
            dev_config = self.device_configs[config_key]
            action = "Skipped"
            if user_input.get(SKIP_DEVICE) is False:
                dev_config[CONF_MAC_ADDRESS] = (
                    user_input.get(CONF_MAC_ADDRESS).replace(":", "").upper()
                )
                dev_config[CONF_MQTT_TOPIC] = user_input.get(CONF_MQTT_TOPIC)

                res_json = await AirbnkApi.getVoltageCfg(
                    self.hass,
                    self.entry_data[CONF_USERID],
                    self.entry_data[CONF_TOKEN],
                    dev_config["deviceType"],
                    dev_config["hardwareVersion"],
                )
                voltage_cfg = []
                if res_json is None:
                    _LOGGER.error(
                        "Failed to retrieve voltage config for device %s", config_key
                    )
                    voltage_cfg = [0, 0, 0, 0]
                else:
                    _LOGGER.debug("Retrieved voltage config: %s", res_json)
                    for i in range(1, 5):
                        voltage_cfg.append(float(res_json["fvoltage" + str(i)]))

                dev_config[CONF_VOLTAGE_THRESHOLDS] = voltage_cfg
                self.entry_data[CONF_DEVICE_CONFIGS][config_key] = dev_config
                action = "Added"

            return self.async_show_form(
                step_id="messagebox",
                data_schema=None,
                errors={},
                description_placeholders={
                    "model": dev_config["deviceType"],
                    "sn": dev_config["sn"],
                    "action": action,
                },
            )
        self.device_index += 1
        if self.device_index < len(self.device_configs):
            return await self.async_step_configure_device()
        return await self._create_entry()

    async def async_step_import(self, user_input):
        """Import a config entry from YAML."""
        _LOGGER.error("This integration does not support configuration via YAML file.")


class AirbnkMqttOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle Transmission client options."""

    def __init__(self, config_entry):
        """Initialize Transmission options flow."""
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        """Manage the Transmission options."""
        if user_input is not None:
            print("UI is {}".format(user_input))
            return self.async_create_entry(title="", data=user_input)

        options = {
            vol.Optional(
                CONF_RETRIES_NUM,
                default=self.config_entry.options.get(
                    CONF_RETRIES_NUM, DEFAULT_RETRIES_NUM
                ),
            ): vol.All(vol.Coerce(int), vol.Range(min=0, max=10)),
        }

        return self.async_show_form(step_id="init", data_schema=vol.Schema(options))
