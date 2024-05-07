#!/usr/bin/python3
from scapy.all import *

# Interface d'ecoute
INTERFACE_VETH = 'canal'

def traiter_trame(pkt):
    if UDP in pkt:

        # Impression du paquet sophistiquee
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        payload = pkt[UDP].payload

        print(f"Source MAC: {src_mac}, Destination MAC: {dst_mac}, Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Destination Port: {dst_port}, Payload: {payload}")

sniff(iface=INTERFACE_VETH, prn=traiter_trame, filter='host 10.87.87.2 and udp')
