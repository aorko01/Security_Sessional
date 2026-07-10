# -*- coding: utf-8 -*-
"""
aes_cipher.py -- block cipher (AES-128/192/256), PKCS#7 padding and the
ECB / CBC modes of operation, built on top of the primitives in aes.py.
"""

import os
import time

from aes import (
    normalize_key,
    substitute_bytes,
    inv_substitute_bytes,
    shift_rows,
    inv_shift_rows,
    mix_columns,
    inv_mix_columns,
    expand_key,
    add_round_key,
)

BLOCK_SIZE = 16

def round_key(words: list, round_no: int) -> bytes:
    key = b""

    start = 4 * round_no

    for i in range(start, start + 4):
        for byte in words[i]:
            key += bytes([byte])

    return key


def encrypt_block(text: bytes, key: list) -> bytes:
    Nr = len(key) // 4 - 1

    state = add_round_key(text, round_key(key, 0))
    for round in range(1, Nr):
        state = substitute_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_key(key, round))

    state = substitute_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_key(key, Nr))

    return state


def decrypt_block(block: bytes, key: list) -> bytes:
    Nr = len(key) // 4 - 1

    state = add_round_key(block, round_key(key, Nr))
    for round in range(Nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_substitute_bytes(state)
        state = add_round_key(state, round_key(key, round))
        state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = inv_substitute_bytes(state)
    state = add_round_key(state, round_key(key, 0))

    return state

def add_padding(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    for _ in range(pad_len):
        data+=bytes([pad_len])
        
    return data


def add_unpadding(data: bytes) -> bytes:
    if not data:
        raise ValueError("cannot unpad empty data")

    pad_len = data[-1]
    if  pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("invalid padding length")
    
    padded_word=b""
    for _ in range(pad_len):
        padded_word+=bytes([pad_len])
    
    if data[-pad_len:] != padded_word:
        raise ValueError("corrupted padded text")

    return data[:-pad_len]



def ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    keys_group = expand_key(key)
    padded = add_padding(plaintext)
    
    if len(padded)%BLOCK_SIZE!=0:
        raise ValueError("Padding not done properly")

    ciphertext = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        ciphertext += encrypt_block(padded[i : i + BLOCK_SIZE], keys_group)

    return bytes(ciphertext)


def ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    words = expand_key(key)
    padded = bytearray()
    
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        padded += decrypt_block(ciphertext[i : i + BLOCK_SIZE], words)

    return add_unpadding(bytes(padded))


def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes = None) -> bytes:
    words = expand_key(key)
    if iv is None:
        iv=os.urandom(BLOCK_SIZE)
    padded = add_padding(plaintext)

    ciphertext = bytearray(iv)
    prev = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        xored = add_round_key(padded[i : i + BLOCK_SIZE], prev)
        cipher_block = encrypt_block(xored, words)
        ciphertext += cipher_block
        prev = cipher_block

    return bytes(ciphertext)


def cbc_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    words = expand_key(key)
    #first cipher text is used for the initial initialization vector 
    iv, body = ciphertext[:BLOCK_SIZE], ciphertext[BLOCK_SIZE:]

    padded = bytearray()
    prev = iv
    for i in range(0, len(body), BLOCK_SIZE):
        block = body[i : i + BLOCK_SIZE]
        decrypted = decrypt_block(block, words)
        padded += add_round_key(decrypted, prev)
        prev = block

    return add_unpadding(bytes(padded))



def _format_hex(data: bytes) -> str:
    return " ".join(f"{b:02x}" for b in data)


def _to_ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)

