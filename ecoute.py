#!/usr/bin/python3
from scapy.all import *
INTERFACE_VETH='canal'
def traiter_trame(t):
	if UDP in t:
		print(t)

sniff(iface=INTERFACE_VETH,prn=traiter_trame,filter='host 10.87.87.2 and udp')
