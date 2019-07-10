#!/usr/bin/env

import scapy.all as scapy
import argparse

"""
A function that performs an ARP request on the broadcast address and receives
a reply

:param target_ip: the IP address or IP address range to perform ARP request upon
:returns: the packet containing the reply to the ARP request
"""

def scan(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast_packet = broadcast_request/arp_request
    answered_packets = scapy.srp(arp_request_broadcast_packet, timeout=1, verbose=0)[0]
    return answered_packets


"""
:return: the IP address argument supplied from the terminal
"""

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--address", dest="ip_address", help="Specify the IP address or"
                                                            "IP address range to be scanned")
    arguments = parser.parse_args()
    if not arguments.ip_address:
        parser.error("[-] Please specify an IP address or IP address range")
    else:
        return arguments


"""
A function the prints the ARP request to the terminal
:param packet: the packet containing the reply to the ARP request
"""


def parse_packets(packet):
    reply_dict_list = []
    for element in packet:
        packet_dict_entry = {"ip":element[1].psrc, "mac":element[1].hwsrc}
        reply_dict_list.append(packet_dict_entry)
    print("\n" + "IP Address" + "\t\t" + "MAC Address" + "\n")
    for dict in reply_dict_list:
        print(dict["ip"] +"\t\t"+ dict["mac"])


args = get_args()
answered_packets = scan(args.ip_address)
parse_packets(answered_packets)

