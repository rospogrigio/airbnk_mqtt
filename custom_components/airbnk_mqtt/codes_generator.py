from __future__ import annotations
import base64
import binascii
import hashlib
import logging
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_LOGGER = logging.getLogger(__name__)

MAX_NORECEIVE_TIME = 30


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


def XOR64Buffer(arr, value):
    for i in range(0, 64):
        arr[i] ^= value
    return arr


def generateWorkingKey(arr, i):
    arr2 = bytearray(72)
    arr2[0 : len(arr)] = arr
    arr2 = XOR64Buffer(arr2, 0x36)
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
    arr3 = XOR64Buffer(arr3, 0x5C)
    arr3[64:84] = arr2sha1
    arr3sha1 = hashlib.sha1(arr3).digest()
    return arr3sha1


def generatePswV2(arr):
    arr2 = bytearray(8)
    for i in range(0, 4):
        b = arr[i + 16]
        i2 = i * 2
        arr2[i2] = arr[(b >> 4) & 15]
        arr2[i2 + 1] = arr[b & 15]
    return arr2


def generateSignatureV2(key, i, arr):
    lenArr = len(arr)
    arr2 = bytearray(lenArr + 68)
    arr2[0:20] = key[0:20]
    arr2 = XOR64Buffer(arr2, 0x36)
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
    arr3 = XOR64Buffer(arr3, 0x5C)
    arr3[64 : 64 + len(arr2sha1)] = arr2sha1
    arr3sha1 = hashlib.sha1(arr3).digest()
    return generatePswV2(arr3sha1)


def getCheckSum(arr, i1, i2):
    c = 0
    for i in range(i1, i2):
        c = c + arr[i]
    return c & 0xFF


class AirbnkCodesGenerator:
    manufactureKey = ""
    bindingkey = ""
    systemTime = 0

    def __init__(self):
        return

    def generateOperationCode(self, lock_dir, curr_lockEvents):
        if lock_dir != 1 and lock_dir != 2:
            return None

        self.systemTime = int(round(time.time()))
        # self.systemTime = 1637590376
        opCode = self.makePackageV3(lock_dir, self.systemTime, curr_lockEvents)
        _LOGGER.debug("OperationCode for dir %s is %s", lock_dir, opCode)

        return opCode

    def makePackageV3(self, lockOp, tStamp, curr_lockEvents):
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
        manKey = self.manufacturerKey[0:16]
        encrypted = AESCipher(manKey).encrypt(toEncrypt, False)
        code[4:20] = encrypted
        workingKey = generateWorkingKey(self.bindingKey, 0)
        signature = generateSignatureV2(workingKey, curr_lockEvents, code[3:20])
        # print("Working Key is {} {} {}".format(workingKey, lockEvents, code[3:20]))
        # print("Signature is {}".format(signature))
        code[20 : 20 + len(signature)] = signature
        code[20 + len(signature)] = getCheckSum(code, 3, 28)
        return binascii.hexlify(code).upper()
        # return code

    def decryptKeys(self, newSnInfo, appKey):
        decr_json = {}
        dec = base64.b64decode(newSnInfo)
        sstr2 = dec[: len(dec) - 10]
        key = appKey[: len(appKey) - 4]
        dec = AESCipher(bytes(key, "utf-8")).decrypt(sstr2, False)
        lockSn = dec[0:16].decode("utf-8").rstrip("\x00")
        decr_json["lockSn"] = lockSn
        decr_json["lockModel"] = dec[80:88].decode("utf-8").rstrip("\x00")
        manKeyEncrypted = dec[16:48]
        bindKeyEncrypted = dec[48:80]
        toHash = bytes(lockSn + appKey, "utf-8")
        hash_object = hashlib.sha1()
        hash_object.update(toHash)
        jdkSHA1 = hash_object.hexdigest()
        key2 = bytes.fromhex(jdkSHA1[0:32])
        self.manufacturerKey = AESCipher(key2).decrypt(manKeyEncrypted, False)
        self.bindingKey = AESCipher(key2).decrypt(bindKeyEncrypted, False)
        return decr_json
