#!-*- coding: utf-8 -*-
from ecdsa import SECP256k1, SigningKey
import hashlib
import random
import os
import requests
import json

def randomString(n):
    return (''.join(map(lambda xx:(hex(xx)[2:]),os.urandom(n))))[0:16]

def get_private_key(hex_string):
    return bytes.fromhex(hex_string.zfill(64))

def get_public_key(private_key):
    # this returns the concatenated x and y coordinates for the supplied private address
    # the prepended 04 is used to signify that it's uncompressed
    return (bytes.fromhex("04")+SigningKey.from_string(private_key, curve=SECP256k1).verifying_key.to_string())

def get_public_address(public_key):
    address = hashlib.sha256(public_key).digest()

    h = hashlib.new('ripemd160')
    h.update(address)
    address = h.digest()
    return address

def base58_encode(version, public_address):

    BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    version = bytes.fromhex(version)
    checksum = hashlib.sha256(hashlib.sha256(version +
    public_address).digest()).digest()[:4]

    payload = version + public_address + checksum

    result = int.from_bytes(payload, byteorder="big")

    # 计算前面的0的数量
    padding = len(payload) - len(payload.lstrip(b'\0'))
    encoded = []

    while result != 0:
        result, remainder = divmod(result, 58)
        encoded.append(BASE58_ALPHABET[remainder])

    return padding*"1" + "".join(encoded)[::-1]


if __name__=='__main__':
    rkey=randomString(64)
    private_key = get_private_key(rkey)
    public_key = get_public_key(private_key)
    public_address = get_public_address(public_key)
    btc_address=base58_encode('00',public_address)
    print("Here. your btc address is {} & your private key is {}".format(btc_address,rkey))
