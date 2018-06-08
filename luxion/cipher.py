#!/usr/bin/env python3

from Crypto.Cipher import AES

NONCE_LENGTH = 16 

def get_cipher(key, nonce):
    global NONCE_LENGTH
    if type(key) == str:
        key = key.encode("utf-8")
    assert type(key) == bytes
    assert type(nonce) == bytes and len(nonce) == NONCE_LENGTH
    key = hmac.new(key, nonce, hashlib.sha256).digest()
    cipher = AES.new(key=key, mode=AES.MODE_CFB, IV=nonce)
    return cipher
