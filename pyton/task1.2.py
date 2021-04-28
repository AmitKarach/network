#!/usr/bin/env python3
from scapy.all import *
a = IP() 
a.dst = '10.9.0.6'
a.src = '1.2.3.4'
b = ICMP () 
p = a/b 
send(p) 
