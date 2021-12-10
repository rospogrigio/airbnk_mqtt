from __future__ import annotations
import base64
import json
import logging
import time
from typing import Callable

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC
from homeassistant.components import mqtt
from homeassistant.core import HomeAssistant, callback

from .const import (
    DOMAIN as AIRBNK_DOMAIN,
    SENSOR_TYPE_STATE,
    SENSOR_TYPE_BATTERY,
    SENSOR_TYPE_VOLTAGE,
    SENSOR_TYPE_LAST_ADVERT,
    SENSOR_TYPE_SIGNAL_STRENGTH,
    LOCK_STATE_LOCKED,
    LOCK_STATE_UNLOCKED,
    LOCK_STATE_JAMMED,
    LOCK_STATE_OPERATING,
    LOCK_STATE_FAILED,
    LOCK_STATE_STRINGS,
    CONF_MAC_ADDRESS,
    CONF_MQTT_TOPIC,
    CONF_VOLTAGE_THRESHOLDS,
    CONF_RETRIES_NUM,
    DEFAULT_RETRIES_NUM,
)

from .codes_generator import AirbnkCodesGenerator

_LOGGER = logging.getLogger(__name__)

MAX_NORECEIVE_TIME = 30

BLEOpTopic = "cmnd/%s/BLEOp"
BLERule1Topic = "cmnd/%s/Rule1"
BLEDetailsTopic = "cmnd/%s/BLEDetails2"
BLEDetailsAllTopic = "cmnd/%s/BLEDetails3"
BLEStateTopic = "tele/%s/BLE"
write_characteristic_UUID = "FFF2"
read_characteristic_UUID = "FFF3"
service_UUID = "FFF0"


class AESCipher:
    """Cipher module for AES decryption."""

    def __init__(self, key):
        """Initialize a new AESCipher."""
        self.block_size = 16
        self.cipher = Cipher(algorithms.AES(key), modes.ECB(), default_backend())

    def encrypt(self, raw, use_base64=True):
        """Encrypt data to be sent to device."""
        encryptor = self.cipher.encryptor()
        crypted_text = encryptor.update(self._pad(raw)) + encryptor.finalize()
        return base64.b64encode(crypted_text) if use_base64 else crypted_text

    def decrypt(self, enc, use_base64=True):
        """Decrypt data from device."""
        if use_base64:
            enc = base64.b64decode(enc)

        decryptor = self.cipher.decryptor()
        return self._unpad(decryptor.update(enc) + decryptor.finalize())

    def _pad(self, data):
        padnum = self.block_size - len(data) % self.block_size
        return data + padnum * chr(padnum).encode()

    @staticmethod
    def _unpad(data):
        return data[: -ord(data[len(data) - 1 :])]


class TasmotaMqttLockDevice:

    utcMinutes = None
    voltage = None
    battery_perc = None
    isBackLock = None
    isInit = None
    isImageA = None
    isHadNewRecord = None
    curr_state = LOCK_STATE_UNLOCKED
    softVersion = None
    isEnableAuto = None
    opensClockwise = None
    isLowBattery = None
    magnetcurr_state = None
    isMagnetEnable = None
    isBABA = None
    lversionOfSoft = None
    sversionOfSoft = None
    serialnumber = None
    lockEvents = 0
    _lockConfig = {}
    _lockData = {}
    _codes_generator = None
    frame1hex = ""
    frame2hex = ""
    frame1sent = False
    frame2sent = False
    last_advert_time = 0
    is_available = False
    retries_num = DEFAULT_RETRIES_NUM
    curr_try = 0

    def __init__(self, hass: HomeAssistant, device_config, entry_options):
        self.hass = hass
        self._callbacks = set()
        self._lockConfig = device_config
        self._codes_generator = AirbnkCodesGenerator()
        self._lockData = self._codes_generator.decryptKeys(
            device_config["newSninfo"], device_config["appKey"]
        )
        self.set_options(entry_options)
        mac_address = self._lockConfig[CONF_MAC_ADDRESS]
        if mac_address is not None and mac_address != "":
            self.requestDetails(mac_address)
        else:
            self.scanAllAdverts()

    @property
    def device_info(self):
        """Return a device description for device registry."""
        devID = self._lockData["lockSn"]
        return {
            "identifiers": {
                # Serial numbers are unique identifiers within a specific domain
                (AIRBNK_DOMAIN, devID)
            },
            "manufacturer": "Airbnk",
            "model": self._lockConfig["deviceType"],
            "name": self._lockConfig["deviceName"],
            "sw_version": self._lockConfig["firmwareVersion"],
            "connections": {
                (CONNECTION_NETWORK_MAC, self._lockConfig[CONF_MAC_ADDRESS])
            },
        }

    def check_availability(self):
        curr_time = int(round(time.time()))
        deltatime = curr_time - self.last_advert_time
        # _LOGGER.debug("Last reply was %s secs ago", deltatime)
        if deltatime >= MAX_NORECEIVE_TIME:
            self.is_available = False

    @property
    def islocked(self) -> bool | None:
        if self.curr_state == LOCK_STATE_LOCKED:
            return True
        else:
            return False

    @property
    def isunlocked(self) -> bool | None:
        if self.curr_state == LOCK_STATE_UNLOCKED:
            return True
        else:
            return False

    @property
    def isjammed(self) -> bool | None:
        if self.curr_state == LOCK_STATE_JAMMED:
            return True
        else:
            return False

    @property
    def state(self):
        return LOCK_STATE_STRINGS[self.curr_state]

    async def mqtt_subscribe(self):
        @callback
        async def message_received(_p0) -> None:
            await self.async_parse_MQTT_message(_p0.payload)

        await mqtt.async_subscribe(
            self.hass,
            BLEStateTopic % self._lockConfig[CONF_MQTT_TOPIC],
            msg_callback=message_received,
        )

    def set_options(self, entry_options):
        """Register callback, called when lock changes state."""
        _LOGGER.debug("Options set: %s", entry_options)
        self.retries_num = entry_options.get(CONF_RETRIES_NUM, DEFAULT_RETRIES_NUM)

    def register_callback(self, callback: Callable[[], None]) -> None:
        """Register callback, called when lock changes state."""
        self._callbacks.add(callback)

    def parse_from_fff3_read_prop(self, sn, barr=[0]):
        # Initialising empty Lockeradvertising variables
        # The init initialiser is used to init object from
        # BLE read properties returned when reading
        # 0Xfff3 characteristic

        # According to type of the lock, checks the byte array
        # and parse using type1 or type2 func
        if barr != [0] and barr is not None:
            if barr[6] == 240:
                self.type1(barr, sn)
            else:
                self.type2(barr, sn)

    async def async_parse_MQTT_message(self, msg):
        _LOGGER.debug("Received msg %s", msg)
        payload = json.loads(msg)
        msg_type = list(payload.keys())[0]
        mac_address = self._lockConfig[CONF_MAC_ADDRESS]
        if "details" in msg_type.lower() and ("p" and "mac" in payload[msg_type]):
            mqtt_advert = payload[msg_type]["p"]
            mqtt_mac = payload[msg_type]["mac"]
            if mac_address is None or mac_address == "":
                sn_hex = "".join(
                    "{:02x}".format(ord(c)) for c in self._lockData["lockSn"]
                )
                if mqtt_advert[24 : 24 + len(sn_hex)] != sn_hex:
                    return
                self._lockConfig[CONF_MAC_ADDRESS] = mqtt_mac
                mac_address = mqtt_mac
                self.requestDetails(mqtt_mac)

            if mqtt_mac == mac_address and len(mqtt_advert) == 62:
                self.parse_MQTT_advert(mqtt_advert[10:])
                time2 = self.last_advert_time
                self.last_advert_time = int(round(time.time()))
                if "RSSI" in payload[msg_type]:
                    rssi = payload[msg_type]["RSSI"]
                    self._lockData[SENSOR_TYPE_SIGNAL_STRENGTH] = rssi

                deltatime = self.last_advert_time - time2
                self._lockData[SENSOR_TYPE_LAST_ADVERT] = deltatime
                if deltatime < MAX_NORECEIVE_TIME:
                    self.is_available = True
                    _LOGGER.debug("Time from last message: %s secs", str(deltatime))
                elif time2 != 0:
                    _LOGGER.error(
                        "Time from last message: %s secs: device unavailable",
                        str(deltatime),
                    )
                    self.is_available = False

                for callback_func in self._callbacks:
                    callback_func()

        if "operation" in msg_type.lower() and ("state" and "MAC" in payload[msg_type]):
            if payload[msg_type]["MAC"] != mac_address:
                return
            msg_state = payload[msg_type]["state"]
            if "FAIL" in msg_state:
                _LOGGER.error("Failed sending frame: returned %s", msg_state)
                self.curr_state = LOCK_STATE_FAILED
                for callback_func in self._callbacks:
                    callback_func()

                if self.curr_try < self.retries_num:
                    self.curr_try += 1
                    time.sleep(0.5)
                    _LOGGER.debug("Retrying: attempt %i", self.curr_try)
                    self.curr_state = LOCK_STATE_OPERATING
                    for callback_func in self._callbacks:
                        callback_func()
                    if self.frame1sent:
                        await self.async_sendFrame2()
                    else:
                        await self.async_sendFrame1()
                else:
                    _LOGGER.error("No more retries: command FAILED")
                    raise Exception("Failed sending frame: returned %s", msg_state)

                return

            msg_written_payload = payload[msg_type]["write"]
            if msg_written_payload == self.frame1hex.upper():
                self.frame1sent = True
                await self.async_sendFrame2()

            if msg_written_payload == self.frame2hex.upper():
                self.frame2sent = True
                for callback_func in self._callbacks:
                    callback_func()

    async def operateLock(self, lock_dir):
        self.curr_try = 0
        _LOGGER.debug("operateLock called (%s): attempt %i", lock_dir, self.curr_try)
        self.frame1sent = False
        self.frame2sent = False
        self.curr_state = LOCK_STATE_OPERATING
        for callback_func in self._callbacks:
            callback_func()

        opCode = self._codes_generator.generateOperationCode(lock_dir, self.lockEvents)
        self.frame1hex = "FF00" + opCode[0:36].decode("utf-8")
        self.frame2hex = "FF01" + opCode[36:].decode("utf-8")

        await self.async_sendFrame1()

    def requestDetails(self, mac_addr):
        mqtt.publish(
            self.hass,
            BLERule1Topic % self._lockConfig[CONF_MQTT_TOPIC],
            "ON Mqtt#Connected DO BLEDetails2 %s ENDON" % mac_addr,
        )
        mqtt.publish(self.hass, BLERule1Topic % self._lockConfig[CONF_MQTT_TOPIC], "1")
        mqtt.publish(
            self.hass, BLEDetailsTopic % self._lockConfig[CONF_MQTT_TOPIC], mac_addr
        )

    def scanAllAdverts(self):
        mqtt.publish(
            self.hass, BLEDetailsAllTopic % self._lockConfig[CONF_MQTT_TOPIC], ""
        )

    async def async_sendFrame1(self):
        mqtt.publish(
            self.hass,
            BLEOpTopic % self._lockConfig[CONF_MQTT_TOPIC],
            self.BLEOPWritePAYLOADGen(self.frame1hex),
        )

    async def async_sendFrame2(self):
        mqtt.publish(
            self.hass,
            BLEOpTopic % self._lockConfig[CONF_MQTT_TOPIC],
            self.BLEOPWritePAYLOADGen(self.frame2hex),
        )

    def BLEOPWritePAYLOADGen(self, frame):
        mac_address = self._lockConfig[CONF_MAC_ADDRESS]
        write_UUID = write_characteristic_UUID
        payload = f"M:{mac_address} s:{service_UUID} c:{write_UUID} w:{frame} go"
        _LOGGER.debug("Sending payload [ %s ]", payload)
        return payload

    def BLEOPreadPAYLOADGen(self):
        mac_address = self._lockData["mac_address"]
        return f"M:{mac_address} s:{service_UUID} c:{read_characteristic_UUID} r go"

    def type1(self, barr, sn):
        self.serialnumber = sn
        self.lockEvents = (
            (barr[10] << 24) | (barr[11] << 16) | (barr[12] << 8) | barr[13]
        )
        self.voltage = ((((barr[14] & 255) << 8) | (barr[15] & 255))) * 0.01
        magnetenableindex = False
        self.isBackLock = (barr[16] & 1) != 0
        self.isInit = (barr[16] & 2) != 0
        self.isImageA = (barr[16] & 4) != 0
        self.isHadNewRecord = (barr[16] & 8) != 0
        i = ((barr[16] & 255) >> 4) & 7

        if i == 0 or i == 5:
            self.curr_state = LOCK_STATE_UNLOCKED
        elif i == 1 or i == 4:
            self.curr_state = LOCK_STATE_LOCKED
        else:
            self.curr_state = LOCK_STATE_JAMMED

        self.softVersion = (
            (str(int(barr[7]))) + "." + (str(int(barr[8]))) + "." + (str(int(barr[9])))
        )
        self.isEnableAuto = (barr[16] & 128) != 0
        self.opensClockwise = (barr[16] & 64) == 0
        self.isLowBattery = (16 & barr[17]) != 0
        self.magnetcurr_state = (barr[17] >> 5) & 3
        if (barr[17] & 128) != 0:
            magnetenableindex = True

        self.isMagnetEnable = magnetenableindex
        self.isBABA = True
        self.parse1(barr, sn)

    # Function used to set properties type2 lock
    def type2(self, barr, sn):
        self.serialnumber = sn
        self.lockEvents = (
            ((barr[8] & 255) << 24)
            | ((barr[9] & 255) << 16)
            | ((barr[10] & 255) << 8)
            | (barr[11] & 255)
        )
        self.utcMinutes = (
            ((barr[12] & 255) << 24)
            | ((barr[13] & 255) << 16)
            | ((barr[14] & 255) << 8)
            | (barr[15] & 255)
        )
        self.voltage = ((barr[16] & 255)) * 0.1
        index = True
        self.isBackLock = (barr[17] & 1) != 0
        self.isInit = (barr[17] & 2) != 0
        self.isImageA = (barr[17] & 4) != 0
        self.isHadNewRecord = (8 & barr[17]) != 0
        self.curr_state = ((barr[17] & 255) >> 4) & 3
        self.isEnableAuto = (barr[17] & 64) != 0
        if (barr[17] & 128) == 0:
            index = False

        self.opensClockwise = index
        self.isBABA = False
        self.parse2(barr, sn)

    def parse2(self, barr, sn):
        if barr is None:
            return None

        barr2 = bytearray(23)
        barr2[0] = 173
        barr2[1] = barr[6]
        barr2[2] = barr[7]
        if sn is not None and len(sn) > 0:
            length = len(sn)
            bytes1 = bytes(sn, "utf-8")
            for i in range(length):

                barr2[i + 3] = bytes1[i]

        barr2[12] = barr[8]
        barr2[13] = barr[9]
        barr2[14] = barr[10]
        barr2[15] = barr[11]
        barr2[16] = barr[12]
        barr2[17] = barr[13]
        barr2[18] = barr[14]
        barr2[19] = barr[15]
        barr2[20] = barr[16]
        barr2[21] = barr[17]
        barr2[22] = barr[18]

        return bytearray.hex(barr2)

    def parse1(self, barr, sn):
        if barr is None:
            return None

        barr2 = bytearray(24)
        barr2[0] = 186
        barr2[1] = 186
        barr2[4] = barr[7]
        barr2[5] = barr[8]
        barr2[6] = barr[9]
        if sn is not None and len(sn) > 0:
            length = len(sn)
            bytes1 = bytes(sn, "utf-8")
            for i in range(length):
                barr2[i + 7] = bytes1[i]

        barr2[16] = barr[14]
        barr2[17] = barr[15]
        barr2[18] = barr[10]
        barr2[19] = barr[11]
        barr2[20] = barr[12]
        barr2[21] = barr[13]
        barr2[22] = barr[16]
        barr2[23] = barr[17]

        return bytearray.hex(barr2)

    def parse_MQTT_advert(self, mqtt_advert):

        bArr = bytearray.fromhex(mqtt_advert)
        if bArr[0] != 0xBA or bArr[1] != 0xBA:
            _LOGGER.error("Wrong advert msg: %s", mqtt_advert)
            return

        self.voltage = ((float)((bArr[16] << 8) | bArr[17])) * 0.01
        self.boardModel = bArr[2]
        self.lversionOfSoft = bArr[3]
        self.sversionOfSoft = (bArr[4] << 16) | (bArr[5] << 8) | bArr[6]
        serialnumber = bArr[7:16].decode("utf-8").strip("\0")
        if serialnumber != self._lockConfig["sn"]:
            _LOGGER.error(
                "ERROR: s/n in advert (%s) is different from cloud data (%s)",
                serialnumber,
                self._lockConfig["sn"],
            )

        lockEvents = (bArr[18] << 24) | (bArr[19] << 16) | (bArr[20] << 8) | bArr[21]
        new_state = (bArr[22] >> 4) & 3
        self.opensClockwise = (bArr[22] & 0x80) != 0
        if self.curr_state < LOCK_STATE_OPERATING or self.lockEvents != lockEvents:
            self.lockEvents = lockEvents
            self.curr_state = new_state
            if self.opensClockwise and self.curr_state is not LOCK_STATE_JAMMED:
                self.curr_state = 1 - self.curr_state

        z = False
        self.isBackLock = (bArr[22] & 1) != 0
        self.isInit = (2 & bArr[22]) != 0
        self.isImageA = (bArr[22] & 4) != 0
        self.isHadNewRecord = (bArr[22] & 8) != 0
        self.isEnableAuto = (bArr[22] & 0x40) != 0
        self.isLowBattery = (bArr[23] & 0x10) != 0
        self.magnetcurr_state = (bArr[23] >> 5) & 3
        if (bArr[23] & 0x80) != 0:
            z = True

        self.isMagnetEnable = z
        self.isBABA = True

        self.battery_perc = self.calculate_battery_percentage(self.voltage)
        self._lockData[SENSOR_TYPE_STATE] = self.state
        self._lockData[SENSOR_TYPE_BATTERY] = self.battery_perc
        self._lockData[SENSOR_TYPE_VOLTAGE] = self.voltage
        # print("LOCK: {}".format(self._lockData))

        return

    def calculate_battery_percentage(self, voltage):
        voltages = self._lockConfig[CONF_VOLTAGE_THRESHOLDS]
        perc = 0
        if voltage >= voltages[2]:
            perc = 100
        elif voltage >= voltages[1]:
            perc = 66.6 + 33.3 * (voltage - voltages[1]) / (voltages[2] - voltages[1])
        else:
            perc = 33.3 + 33.3 * (voltage - voltages[0]) / (voltages[1] - voltages[0])
        perc = max(perc, 0)
        return round(perc, 1)
