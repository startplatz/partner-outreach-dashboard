#!/usr/bin/env python3
"""Verschluesselt data.xlsx -> data.enc (AES-256-GCM, PBKDF2-SHA256 300k).
Format: MAGIC(8) + salt(16) + iv(12) + ciphertext(+tag).
Nach jeder Aktualisierung der Excel ausfuehren: python3 encrypt_data.py
"""
import os, sys, getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PW = os.environ.get('DASH_PW') or getpass.getpass('Passwort: ')
salt = os.urandom(16); iv = os.urandom(12)
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=300000).derive(PW.encode())
data = open('data.xlsx','rb').read()
ct = AESGCM(key).encrypt(iv, data, None)
open('data.enc','wb').write(b'SPDASH01' + salt + iv + ct)
print('data.enc geschrieben:', len(ct)+36, 'bytes')
