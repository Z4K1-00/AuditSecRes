#!/usr/bin/python3

from scapy.all import *

def forward_packet(packet):
	# Craft ICMP Echo Request packet with the encapsulated original packet
	icmp_packet = IP(src="192.168.10.1", dst="192.168.10.3") / ICMP(type="echo-request") / packet[IP]
	# Send the encapsulated packet to the destination IP address
	frags = fragment(icmp_packet, fragsize=1500)
	for frag in frags :
		send(frag, iface='h1-eth0')

# Sniff packets on the canal interface and forward them
sniff(iface='canal', prn=forward_packet)
