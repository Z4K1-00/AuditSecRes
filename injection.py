#!/usr/bin/python3
from scapy.all import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

INTERFACE_INJECTION = 'injection'
original_payload = b"Hello"  # Contenu du datagramme 

# Exemple de cle partagee pour chiffrement AES
key = b"abcdefghijklmnop"

# Vecteur d'initialisation
iv = b"RandomIV12345678"

# Processus de chiffrement
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
padder = padding.PKCS7(128).padder()
padded_payload = padder.update(original_payload) + padder.finalize()
encrypted_payload = encryptor.update(padded_payload) + encryptor.finalize()

# Injection de paquet UDP
sendp(Ether(src=RandMAC(), dst='32:de:9c:12:73:e0') /
      IP(src='10.87.87.1', dst='10.87.87.2') /
      UDP(sport=5678, dport=6789) /
      encrypted_payload, iface=INTERFACE_INJECTION)

# Injection de paquet TCP
sendp(Ether(src=RandMAC(), dst='32:de:9c:12:73:e0') /
      IP(src='10.87.87.1', dst='10.87.87.2') /
      TCP(sport=5678, dport=6789, flags='S'), iface=INTERFACE_INJECTION)