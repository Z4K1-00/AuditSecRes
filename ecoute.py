#!/usr/bin/python3
from scapy.all import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

INTERFACE_VETH = 'canal'
key = b"abcdefghijklmnop"  # Use the same key as used for encryption
iv = b"RandomIV12345678"  # Use the same IV as used for encryption

def decrypt_payload(encrypted_payload):
    # Initialize AES cipher with CBC mode and the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the payload
    decrypted_payload = decryptor.update(encrypted_payload) + decryptor.finalize()

    # Unpad the decrypted payload
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_payload = unpadder.update(decrypted_payload) + unpadder.finalize()

    return unpadded_payload

def traiter_trame(pkt):
    if UDP in pkt:
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        encrypted_payload = bytes(pkt[UDP].payload)

        # Decrypt the payload
        decrypted_payload = decrypt_payload(encrypted_payload)

        print(f"Source MAC: {src_mac}, Destination MAC: {dst_mac}, Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Destination Port: {dst_port}, Payload: {decrypted_payload}")

sniff(iface=INTERFACE_VETH, prn=traiter_trame, filter='host 10.87.87.2 and udp')
