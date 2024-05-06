#!/usr/bin/python3
from scapy.all import *

def decapsulate_and_forward(pkt):
    # Check if it's an ICMP packet with payload
    if ICMP in pkt and pkt[ICMP].type == 8 and pkt.haslayer(Raw):
        # Extract the payload (original packet) from the ICMP packet
        original_packet = pkt[Raw].load

        # Forward the decapsulated packet to the canal interface
        sendp(original_packet, iface='injection')

# Sniff ICMP packets on the interface and decapsulate and forward them
sniff(iface='h3-eth0', prn=decapsulate_and_forward, filter='icmp')

