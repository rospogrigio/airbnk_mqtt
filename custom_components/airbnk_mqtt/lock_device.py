from __future__ import annotations
import base64
import binascii
import hashlib
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
)

_LOGGER = logging.getLogger(__name__)

MAX_NORECEIVE_TIME = 30

BLETelemetryTopic = "%s/tele"
BLEOpTopic = "%s/command"
BLEStateTopic = "%s/adv"
BLEOperationReportTopic = "%s/command_result"


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


class AirbnkLockMqttDevice:

    utcMinutes = None
    battery = None
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
    versionOfSoft = None
    versionCode = None
    serialnumber = None
    lockEvents = 0
    _lockConfig = {}
    _lockData = {}
    lockModel = ""
    lockSn = ""
    manufactureKey = ""
    bindingkey = ""
    systemTime = 0
    cmd = {}
    cmdSent = False
    last_advert_time = 0
    is_available = False

    def __init__(self, hass: HomeAssistant, device_config):
        self.hass = hass
        self._callbacks = set()
        self._lockConfig = device_config
        self._lockData = self.decryptKeys(
            device_config["newSninfo"], device_config["appKey"]
        )

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
        async def adv_received(_p0) -> None:
            self.parse_adv_message(_p0.payload)

        @callback
        async def operation_msg_received(_p0) -> None:
            self.parse_operation_message(_p0.payload)

        @callback
        async def telemetry_msg_received(_p0) -> None:
            self.parse_telemetry_message(_p0.payload)

        await mqtt.async_subscribe(
            self.hass,
            BLEStateTopic % self._lockConfig[CONF_MQTT_TOPIC],
            msg_callback=adv_received,
        )
        await mqtt.async_subscribe(
            self.hass,
            BLETelemetryTopic % self._lockConfig[CONF_MQTT_TOPIC],
            msg_callback=telemetry_msg_received,
        )
        await mqtt.async_subscribe(
            self.hass,
            BLEOperationReportTopic % self._lockConfig[CONF_MQTT_TOPIC],
            msg_callback=operation_msg_received,
        )

    def register_callback(self, callback: Callable[[], None]) -> None:
        """Register callback, called when lock changes state."""
        self._callbacks.add(callback)

    def parse_telemetry_message(self, msg):
        # TODO
        _LOGGER.debug("Received telemetry %s", msg)

    def parse_adv_message(self, msg):
        _LOGGER.debug("Received adv %s", msg)
        payload = json.loads(msg)
        mac_address = self._lockConfig[CONF_MAC_ADDRESS]
        mqtt_advert = payload["data"]
        mqtt_mac = payload["mac"].replace(":", "").upper()
        _LOGGER.debug("Config mac %s, received %s", mac_address, mqtt_mac)
        if mqtt_mac != mac_address.upper():
            return

        self.parse_MQTT_advert(mqtt_advert.upper())
        time2 = self.last_advert_time
        self.last_advert_time = int(round(time.time()))
        if "rssi" in payload:
            rssi = payload["rssi"]
            self._lockData[SENSOR_TYPE_SIGNAL_STRENGTH] = rssi

        deltatime = self.last_advert_time - time2
        self._lockData[SENSOR_TYPE_LAST_ADVERT] = deltatime
        self.is_available = True
        _LOGGER.debug("Time from last message: %s secs", str(deltatime))

        for callback_func in self._callbacks:
            callback_func()

    def parse_operation_message(self, msg):
        _LOGGER.debug("Received operation result %s", msg)
        payload = json.loads(msg)
        mac_address = self._lockConfig[CONF_MAC_ADDRESS]
        mqtt_mac = payload["mac"].replace(":", "").upper()

        if mqtt_mac != mac_address.upper():
            return

        msg_state = payload["success"]
        if msg_state == False:
            _LOGGER.error("Failed sending command: returned %s", msg_state)
            self.curr_state = LOCK_STATE_FAILED
            raise Exception("Failed sending command: returned %s", msg_state)
            return

        msg_sign = payload["sign"]
        if msg_sign == self.cmd["sign"]:
            self.cmdSent = True

        for callback_func in self._callbacks:
            callback_func()

    async def operateLock(self, lock_dir):
        _LOGGER.debug("operateLock called (%s)", lock_dir)
        self.cmdSent = False
        self.curr_state = LOCK_STATE_OPERATING
        for callback_func in self._callbacks:
            callback_func()

        self.generateOperationCode(lock_dir)
        mqtt.publish(
            self.hass,
            BLEOpTopic % self._lockConfig[CONF_MQTT_TOPIC],
            json.dumps(self.cmd),
        )

    def XOR64Buffer(self, arr, value):
        for i in range(0, 64):
            arr[i] ^= value
        return arr

    def generateWorkingKey(self, arr, i):
        arr2 = bytearray(72)
        arr2[0 : len(arr)] = arr
        arr2 = self.XOR64Buffer(arr2, 0x36)
        arr2[71] = i & 0xFF
        i = i >> 8
        arr2[70] = i & 0xFF
        i = i >> 8
        arr2[69] = i & 0xFF
        i = i >> 8
        arr2[68] = i & 0xFF
        arr2sha1 = hashlib.sha1(arr2).digest()
        arr3 = bytearray(84)
        arr3[0 : len(arr)] = arr
        arr3 = self.XOR64Buffer(arr3, 0x5C)
        arr3[64:84] = arr2sha1
        arr3sha1 = hashlib.sha1(arr3).digest()
        return arr3sha1

    def generatePswV2(self, arr):
        arr2 = bytearray(8)
        for i in range(0, 4):
            b = arr[i + 16]
            i2 = i * 2
            arr2[i2] = arr[(b >> 4) & 15]
            arr2[i2 + 1] = arr[b & 15]
        return arr2

    def generateSignatureV2(self, key, i, arr):
        lenArr = len(arr)
        arr2 = bytearray(lenArr + 68)
        arr2[0:20] = key[0:20]
        arr2 = self.XOR64Buffer(arr2, 0x36)
        arr2[64 : 64 + lenArr] = arr
        arr2[lenArr + 67] = i & 0xFF
        i = i >> 8
        arr2[lenArr + 66] = i & 0xFF
        i = i >> 8
        arr2[lenArr + 65] = i & 0xFF
        i = i >> 8
        arr2[lenArr + 64] = i & 0xFF
        arr2sha1 = hashlib.sha1(arr2).digest()
        arr3 = bytearray(84)
        arr3[0:20] = key[0:20]
        arr3 = self.XOR64Buffer(arr3, 0x5C)
        arr3[64 : 64 + len(arr2sha1)] = arr2sha1
        arr3sha1 = hashlib.sha1(arr3).digest()
        return self.generatePswV2(arr3sha1)

    def getCheckSum(self, arr, i1, i2):
        c = 0
        for i in range(i1, i2):
            c = c + arr[i]
        return c & 0xFF

    def makePackageV3(self, lockOp, tStamp):
        code = bytearray(36)
        code[0] = 0xAA
        code[1] = 0x10
        code[2] = 0x1A
        code[3] = code[4] = 3
        code[5] = 16 + lockOp
        code[8] = 1
        code[12] = tStamp & 0xFF
        tStamp = tStamp >> 8
        code[11] = tStamp & 0xFF
        tStamp = tStamp >> 8
        code[10] = tStamp & 0xFF
        tStamp = tStamp >> 8
        code[9] = tStamp & 0xFF
        toEncrypt = code[4:18]
        manKey = self._lockData["manufacturerKey"][0:16]
        encrypted = AESCipher(manKey).encrypt(toEncrypt, False)
        code[4:20] = encrypted
        workingKey = self.generateWorkingKey(self._lockData["bindingKey"], 0)
        signature = self.generateSignatureV2(workingKey, self.lockEvents, code[3:20])
        # print("Working Key is {} {} {}".format(workingKey, lockEvents, code[3:20]))
        # print("Signature is {}".format(signature))
        code[20 : 20 + len(signature)] = signature
        code[20 + len(signature)] = self.getCheckSum(code, 3, 28)
        return binascii.hexlify(code).upper()
        # return code

    def parse_MQTT_advert(self, mqtt_advert):
        _LOGGER.debug("Parsing advert msg: %s", mqtt_advert)
        bArr = bytearray.fromhex(mqtt_advert)
        if bArr[0] != 0xBA or bArr[1] != 0xBA:
            _LOGGER.error("Wrong advert msg: %s", mqtt_advert)
            return

        self.battery = ((float)((bArr[16] << 8) | bArr[17])) * 0.1
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

        self._lockData[SENSOR_TYPE_STATE] = self.state
        self._lockData[SENSOR_TYPE_BATTERY] = self.battery
        # print("LOCK: {}".format(self._lockData))

        return

    def generateOperationCode(self, lock_dir):
        if lock_dir != 1 and lock_dir != 2:
            return None

        self.systemTime = int(round(time.time()))
        # self.systemTime = 1637590376
        opCode = self.makePackageV3(lock_dir, self.systemTime)
        _LOGGER.debug("OperationCode for dir %s is %s", lock_dir, opCode)
        json = {}
        json["command1"] = "FF00" + opCode[0:36].decode("utf-8")
        json["command2"] = "FF01" + opCode[36:].decode("utf-8")
        json["sign"] = self.systemTime
        self.cmd = json
        return opCode

    def decryptKeys(self, newSnInfo, appKey):
        json = {}
        dec = base64.b64decode(newSnInfo)
        sstr2 = dec[: len(dec) - 10]
        key = appKey[: len(appKey) - 4]
        dec = AESCipher(bytes(key, "utf-8")).decrypt(sstr2, False)
        lockSn = dec[0:16].decode("utf-8").rstrip("\x00")
        json["lockSn"] = lockSn
        json["lockModel"] = dec[80:88].decode("utf-8").rstrip("\x00")
        manKeyEncrypted = dec[16:48]
        bindKeyEncrypted = dec[48:80]
        toHash = bytes(lockSn + appKey, "utf-8")
        hash_object = hashlib.sha1()
        hash_object.update(toHash)
        jdkSHA1 = hash_object.hexdigest()
        key2 = bytes.fromhex(jdkSHA1[0:32])
        json["manufacturerKey"] = AESCipher(key2).decrypt(manKeyEncrypted, False)
        json["bindingKey"] = AESCipher(key2).decrypt(bindKeyEncrypted, False)
        return json
