#!/usr/bin/env

import scapy.all as scapy

def scan(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast_packet = arp_request/broadcast_request
    answered_packets = scapy.srp(arp_request_broadcast_packet, timeout=1)[0]
    print(answered_packets)


ip = "192.168.0.1/24"
scan("192.168.0.1/24")

