#!/usr/bin/env
import scapy.all as scapy
from scapy.layers import http

def initialise():
    scapy.sniff("eth0", store=False, prn=filter_packets)

def filter_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(url)
initialise()