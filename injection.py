#!/usr/bin/python3
from scapy.all import *
INTERFACE_INJECTION='injection'
# Injection de paquets UDPs
sendp(Ether(src='b6:66:ec:dc:f3:68',dst='06:30:9b:a3:c1:f5')/IP(src='10.87.87.1',dst='10.87.87.2')/
UDP(sport=5678,dport=6789)/"Hello",iface=INTERFACE_INJECTION)
# Injection de paquets TCPs
sendp(Ether(src='b6:66:ec:dc:f3:68',dst='06:30:9b:a3:c1:f5')/IP(src='10.87.87.1',dst='10.87.87.2')/
TCP(sport=5678,dport=6789,flags='S'),iface=INTERFACE_INJECTION)
