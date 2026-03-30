import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16


def encrypt_file(data, key):

    cipher = AES.new(key, AES.MODE_CBC)

    ciphertext = cipher.encrypt(pad(data, BLOCK_SIZE))

    return cipher.iv + ciphertext


def decrypt_file(data, key):

    iv = data[:16]

    ciphertext = data[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)

    return plaintext