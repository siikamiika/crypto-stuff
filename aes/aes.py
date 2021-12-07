#!/usr/bin/env python3

import os
from Crypto.Cipher import AES

# cryptographically secure randomness
key = os.urandom(16)
original_iv = os.urandom(16)

def encrypt(plaintext, key, iv):
    return AES.new(key, mode=AES.MODE_CBC, IV=iv).encrypt(plaintext)

def decrypt(ciphertext, key, iv):
    return AES.new(key, mode=AES.MODE_CBC, IV=iv).decrypt(ciphertext)

plaintext = b'0123456789abcdef'
print(f'key={key}')
print(f'iv={original_iv}')
print(f'encrypting {plaintext} with key, iv')
ciphertext = encrypt(plaintext, key, original_iv)
print(f'encrypted to {ciphertext}')
if decrypt(ciphertext, key, original_iv) == plaintext:
    print(f'ciphertext decrypted correctly back to {plaintext}')
print()

# attack on AES-CBC: rewrite known plaintext in first block
print('transmit (ciphertext, original_iv) over untrusted medium')
print('attacker knows the contents and alters it by modifying the IV')
attacker_plaintext = b'fedcba9876543210'
print(f'plaintext={plaintext}')
print(f'attacker_plaintext={attacker_plaintext}')
attacker_iv_mask = bytes(a ^ b for a, b in zip(plaintext, attacker_plaintext))
print(f'attacker obtains attacker_iv_mask = {attacker_iv_mask} by doing plaintext XOR attacker_plaintext')
attacker_iv = bytes(a ^ b for a, b in zip(original_iv, attacker_iv_mask))
print('attacker sends (ciphertext, attacker_iv) to recipient where attacker_iv = original_iv XOR attacker_iv_mask')
modified_plaintext = decrypt(ciphertext, key, attacker_iv)
print(f'the message now decrypts to {modified_plaintext}')
