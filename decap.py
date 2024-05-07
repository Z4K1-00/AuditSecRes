#!/usr/bin/python3
from scapy.all import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

key = b"abcdefghijklmnop"  # la cle pre-partagee
iv = b"RandomIV12345678"  # le meme vecteur d'initialisation

# Fonction de dechiffrement
def decrypt_payload(encrypted_payload):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_payload = decryptor.update(encrypted_payload) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_payload = unpadder.update(decrypted_payload) + unpadder.finalize()

    return unpadded_payload

# Fonction pour la decapsulation et l'envoi du packet udp et tcp
def decapsulate_and_forward(pkt):
    
    # Verifier qu'il s'agit d'une demande 'echo' (ping) et qu'il y a un paquet encapsule dedans
    if ICMP in pkt and pkt[ICMP].type == 8 and Raw in pkt:
        
        # Extraction du paquet encapsule dedans
        icmp_payload = pkt[Raw].load
        original_packet = Ether(icmp_payload)
        
        # Envoi du paquet TCP
        if TCP in original_packet:
            sendp(original_packet, iface='injection')

        # Dechiffrement du datagramme puis envoie du paquet udp
        if UDP in original_packet:
            udp_packet = original_packet[UDP]

            # Processus du dechiffrement
            encrypted_payload = bytes(udp_packet.payload)
            decrypted_payload = decrypt_payload(encrypted_payload)
                
            # reconsttruction du paquet udp avec le datagramme dechiffre
            new_packet = Ether(src=original_packet[Ether].src, dst=original_packet[Ether].dst) / IP(dst=original_packet[IP].dst, src=original_packet[IP].src) / UDP(dport=udp_packet.dport, sport=udp_packet.sport) / decrypted_payload
            
            #Envoi du paquet udp original
            sendp(new_packet, iface='injection')

sniff(iface='h3-eth0', prn=decapsulate_and_forward, filter='icmp')

