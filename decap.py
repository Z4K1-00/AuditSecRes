#!/usr/bin/python3
from scapy.all import *

def decapsulate_and_forward(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8 and pkt.haslayer(Raw):
        # Reassemble fragmented packets
        reassembled_packet = defragment(pkt)

        if reassembled_packet:
            # Extract the payload (original packet) from the reassembled packet
            original_payload = b""
            for frag in reassembled_packet:
                if Raw in frag:
                    original_payload += frag[Raw].load

            # Craft the original packet
            original_packet = Ether() / IP() / original_payload

            # Forward the decapsulated packet to the canal interface
            sendp(original_packet, iface='canal')

# Sniff ICMP packets on the interface and decapsulate and forward them
sniff(iface='h3-eth0', prn=decapsulate_and_forward, filter='icmp')

