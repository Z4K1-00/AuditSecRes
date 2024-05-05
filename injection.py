#!/usr/bin/python3
from scapy.all import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

INTERFACE_INJECTION = 'injection'
original_payload = b"Hello"  # Convert string to bytes

# Generate a random 16-byte key
key = b"abcdefghijklmnop"

# Initialize AES cipher with CBC mode and generate a random IV
iv = b"RandomIV12345678"
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Pad the payload to be a multiple of the block size
padder = padding.PKCS7(128).padder()
padded_payload = padder.update(original_payload) + padder.finalize()

# Encrypt the padded payload
encrypted_payload = encryptor.update(padded_payload) + encryptor.finalize()

# Injection de paquets UDPs
sendp(Ether(src=RandMAC(), dst='2a:87:08:d1:8f:99') /
      IP(src='10.87.87.1', dst='10.87.87.2') /
      UDP(sport=5678, dport=6789) /
      encrypted_payload, iface=INTERFACE_INJECTION)

# Injection de paquets TCPs
sendp(Ether(src=RandMAC(), dst='2a:87:08:d1:8f:99') /
      IP(src='10.87.87.1', dst='10.87.87.2') /
      TCP(sport=5678, dport=6789, flags='S'), iface=INTERFACE_INJECTION)
