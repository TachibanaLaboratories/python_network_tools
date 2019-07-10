#!/usr/bin/env

import scapy.all as scapy
import argparse

def scan(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast_packet = broadcast_request/arp_request
    answered_packets = scapy.srp(arp_request_broadcast_packet, timeout=1, verbose=0)[0]
    return answered_packets


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--address", dest="ip_address", help="Specify the IP address or"
                                                            "IP address range to be scanned")
    arguments = parser.parse_args()
    if not arguments.ip_address:
        parser.error("[-] Please specify an IP address or IP address range")
    else:
        return arguments


def parse_packets(packet):
    for element in packet:
        print(element)


args = get_args()
answered_packets = scan(args.ip_address)
parse_packets(answered_packets)

