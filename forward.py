#!/usr/bin/python3

from scapy.all import *

def forward_packet(packet):
	# Encapsuler le paquet injecte dans un paquet icmp
	icmp_packet = IP(src="192.168.10.1", dst="192.168.10.3") / ICMP(type="echo-request") / packet
	# Envoyer le paquet encapsule
	send(icmp_packet, iface='h1-eth0')

# Attendre l'injection du paquet UDP/TCP
sniff(iface='canal', prn=forward_packet)
