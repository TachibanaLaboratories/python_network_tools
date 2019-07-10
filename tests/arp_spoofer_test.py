#!/usr/bin/env
import scapy.all as scapy
import argparse
import time
import subprocess

def get_mac(dest_ip):
    arp_request = scapy.ARP(pdst=dest_ip)
    broadcast_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast_packet = broadcast_request / arp_request
    answered_packets = scapy.srp(arp_request_broadcast_packet, timeout=1, verbose=False)[0]
    print(answered_packets[0][1].hwsrc)


get_mac("10.0.2.2")