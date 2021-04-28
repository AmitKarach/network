#!/usr/bin/env python3
from scapy.all import *
hostname = "google.com"
tmp = ""
counter=1
print ("Starting tracerout to",hostname, "...")
paketa = IP(dst=hostname, ttl=1) / ICMP()
reply = sr1(paketa)
while reply.src != tmp:
	if reply is None:
        	print ("error")
        	break
	counter= counter+1
	tmp = reply.src
	paketa = IP(dst=hostname, ttl=counter) / ICMP()
	reply = sr1(paketa)
print ("It took", counter ,"routers to get to the server of", hostname, "with the IP", reply.src)


