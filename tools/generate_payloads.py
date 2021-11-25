#!/usr/bin/python3
#
# TuyaPower (Tuya Power Stats)
#      Power Probe - Wattage of smart devices - JSON Output

import base64
import binascii
import hashlib
import json
import logging
import socket
import time
import binascii
import struct
import sys
from operator import xor
from collections import namedtuple
from contextlib import contextmanager

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_LOGGER = logging.getLogger("test")
_LOGGER.setLevel(level=logging.DEBUG)  # Debug hack!

from Crypto.Cipher import AES
import base64
import re

# Paste here the values you find in the logs after enabling debug ( "custom_components.airbnk: debug" in configuration.yaml ):
newSnInfo = 'HTWsm....yTj2w=='
appKey = "..."

# Paste here the log advertisement value you can get from nRF Connect:
lockAdv = b'0201...1BFFBABA...'
#           0 1 2 3 4 5 6 7 8 9 101112131415161718192021222324252627


class AESCipher:
    """Cipher module for Tuya communication."""

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



def _decode_payload(payload):
    _LOGGER.debug("decode payload=%r", payload)

    version=3.3

    if payload.startswith(PROTOCOL_VERSION_BYTES_31):
        payload = payload[len(PROTOCOL_VERSION_BYTES_31) :]  # remove version header
        # remove (what I'm guessing, but not confirmed is) 16-bytes of MD5
        # hexdigest of payload
        payload = cipher.decrypt(payload[16:])
    elif version == 3.3:
        if payload.startswith(
            PROTOCOL_VERSION_BYTES_33
        ):
            payload = payload[len(PROTOCOL_33_HEADER) :]
        print("todecrypt payload [{}]".format(payload))
        payload = cipher.decrypt(payload, False)
        print("decrypted payload [{}]".format(payload))
        _LOGGER.debug("decrypted payload=%r", payload)

#        if "data unvalid" in payload:
#            self.dev_type = "type_0d"
#            _LOGGER.debug(
#                "'data unvalid' error detected: switching to dev_type %r",
#                self.dev_type,
#            )
#            return None
    elif not payload.startswith(b"{"):
        raise Exception(f"Unexpected payload={payload}")

    if not isinstance(payload, str):
        payload = payload.decode()
    _LOGGER.debug("decrypted result=%r", payload)
    return json.loads(payload)

#def str2HexStr(String str):
#        char[] charArray = "0123456789ABCdef".toCharArray();
#        StringBuilder sb = new StringBuilder("");
#        byte[] bytes = str.getBytes();
#        for (int i = 0; i < bytes.length; i++) {
#            sb.append(charArray[(bytes[i] & 240) >> 4]);
#            sb.append(charArray[bytes[i] & 15]);
#        }
#        return sb.toString().trim();
#    }

def dispose(str, str2):
    dec = base64.b64decode(str)
    #print("PRE  {} {}".format(dec, len(dec)))
    #bf1 = binascii.hexlify(dec) # bytesToHexFun1(dec)
    sstr = dec[-10:]
    sstr2 = dec[:len(dec)-10]
    # print("POST {} {}".format(sstr2, len(sstr2)))
    key = str2[:len(str2)-4]
    # print("KEY  {} {}".format(key, len(key)))
    dec = AESCipher(bytes(key,'utf-8')).decrypt(sstr2, False)
    # print("DEC {} {}".format(dec, len(dec)))
    json = {}
    lockSn = dec[0:16].decode('utf-8').rstrip('\x00')
    lockType = dec[80:88].decode('utf-8').rstrip('\x00')
    manKeyEncrypted = dec[16:48]
    bindKeyEncrypted = dec[48:80]
    # print("SN {} {}".format(lockSn, lockType))
    # print("ENC {} {}".format(manKeyEncrypted, bindKeyEncrypted))
    #toHash = bytearray("".join("{:02x}".format(ord(c)) for c in (lockSn+str2)),'utf-8')
    toHash = bytes(lockSn+str2, 'utf-8')
    hash_object = hashlib.sha1()
    hash_object.update(toHash)
    jdkSHA1 = hash_object.hexdigest()
    key2 = bytes.fromhex(jdkSHA1[0:32])
    # print("SHA1 {} -> {}".format(toHash, key2))
    manKey = AESCipher(key2).decrypt(manKeyEncrypted, False)
    # print("DEC MANKEY {}".format(manKey))
    bindKey = AESCipher(key2).decrypt(bindKeyEncrypted, False)
    # print("DEC BINDKEY {}".format(bindKey))
    #jdkSHA1 = hashlib.sha1(str(toHash).encode('utf-8')).digest()
    return { "lockSn": lockSn, "lockType": lockType, "manufacturerKey": manKey, "bindingKey": bindKey,  }

def XOR64Buffer(arr, value):
    for i in range(0,64):
        arr[i] ^= value
    return arr

def generateWorkingKey(arr, i):
    arr2 = bytearray(72)
    arr2[0:len(arr)] = arr
    # print("ARR  IS {}".format(arr))
    arr2 = XOR64Buffer(arr2, 0x36)
    arr2[71] = (i & 0xFF)
    i = i >> 8
    arr2[70] = (i & 0xFF)
    i = i >> 8
    arr2[69] = (i & 0xFF)
    i = i >> 8
    arr2[68] = (i & 0xFF)
    # print("ARR2 IS {} {}".format(arr2,len(arr2)))
    arr2sha1 = hashlib.sha1(arr2).digest()
    # print("ARR2SHA IS {} {}".format(arr2sha1,len(arr2sha1)))
    arr3 = bytearray(84)
    arr3[0:len(arr)] = arr
    arr3 = XOR64Buffer(arr3, 0x5c)
    arr3[64:84] = arr2sha1
    # print("ARR3 IS {} {}".format(arr3,len(arr3)))
    arr3sha1 = hashlib.sha1(arr3).digest()
    # print("ARR3SHA IS {} {}".format(arr3sha1,len(arr3sha1)))
    return arr3sha1

def generatePswV2(arr):
    arr2 = bytearray(8)
    for i in range(0, 4):
        b = arr[i+16]
        i2 = i * 2
        arr2[i2] = arr[(b >> 4) & 15]
        arr2[i2 + 1] = arr[b & 15]
    return arr2


def generateSignatureV2(key, i, arr):
    #print("ARR IS {} {}".format(arr,len(arr)))
    lenArr = len(arr)
    arr2 = bytearray(lenArr+68)
    arr2[0:20] = key[0:20]
    arr2 = XOR64Buffer(arr2, 0x36)
    arr2[64:64+lenArr] = arr
    arr2[lenArr+67] = (i & 0xFF)
    i = i >> 8
    arr2[lenArr+66] = (i & 0xFF)
    i = i >> 8
    arr2[lenArr+65] = (i & 0xFF)
    i = i >> 8
    arr2[lenArr+64] = (i & 0xFF)
    # print("ARR2 IS {} {}".format(arr2,len(arr2)))
    arr2sha1 = hashlib.sha1(arr2).digest()
    # print("ARR2SHA IS {} {}".format(arr2sha1,len(arr2sha1)))
    arr3 = bytearray(84)
    arr3[0:20] = key[0:20]
    arr3 = XOR64Buffer(arr3, 0x5c)
    arr3[64:64+len(arr2sha1)] = arr2sha1
    # print("ARR3 IS {} {}".format(arr3,len(arr3)))
    arr3sha1 = hashlib.sha1(arr3).digest()
    # print("ARR3SHA IS {} {}".format(arr3sha1,len(arr3sha1)))
    return generatePswV2(arr3sha1)

def getCheckSum(arr, i1, i2):
    c = 0
    for i in range(i1, i2):
        c = c + arr[i]
    return (c & 0xFF)

def makePackageV3(advInfo, lockInfo, lockOp, tStamp):
    code = bytearray(36)
    code[0] = 0xAA
    code[1] = 16
    code[2] = 26
    code[3] = code[4] = 3
    code[5] = 16 + lockOp
    code[8] = 1
    code[12] = (tStamp & 0xFF)
    tStamp = tStamp >> 8
    code[11] = (tStamp & 0xFF)
    tStamp = tStamp >> 8
    code[10] = (tStamp & 0xFF)
    tStamp = tStamp >> 8
    code[9] = (tStamp & 0xFF)
    toEncrypt = code[4:18]
    manKey = lockInfo["manufacturerKey"][0:16]
    encrypted = AESCipher(manKey).encrypt(toEncrypt, False)
    # print("CODE IS {} {} {}".format(code, len(code), encrypted))
    code[4:20] = encrypted
    # print("CODE IS {} {}".format(code, len(code)))
    lockEventsStr = advInfo[46:54]
    lockEvents = int(lockEventsStr, 16)
    # print("LOCK EVENTS {} {}".format(advInfo, lockEvents))
    workingKey = generateWorkingKey(lockInfo["bindingKey"], 0)
    signature = generateSignatureV2(workingKey, lockEvents, code[3:20])
    # print("SIGN: {}".format(signature))
    code[20:20+len(signature)] = signature
    code[20+len(signature)] = getCheckSum(code, 3, 28)
    # print("CODE IS {} {}".format(code, len(code)))
    return binascii.hexlify(code).upper()


lockDir = 1

if len(sys.argv) > 1:
    lockDir = int(sys.argv[1])

if lockDir not in [1,2]:
    print("BAD PARAMETER ({}): exiting.".format(lockDir))
    exit(-1)

dirs=["OPENING", "CLOSING"]

lockInfo = dispose(newSnInfo, appKey)
print("DECRYPTED KEYS: {}".format(lockInfo))

currTime = 1636707960
currTime = int(time.time())
print("TIME IS {}".format(currTime))


opCode = makePackageV3(lockAdv, lockInfo, lockDir, currTime)

print("OPCODE FOR {} IS {}".format(dirs[lockDir-1], opCode))
opCode1 = "FF00" + opCode[0:36].decode('utf-8')
opCode2 = "FF01" + opCode[36:].decode('utf-8')
print("PACKET 1 IS {}".format(opCode1))
print("PACKET 2 IS {}".format(opCode2))

