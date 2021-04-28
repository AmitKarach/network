#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):	
	pkt.show()
print("starting to sniff")
pkt = sniff(filter='tcp or icmp', prn=print_pkt)


