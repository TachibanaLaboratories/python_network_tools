#!/usr/bin/env
import scapy.all as scapy
#from scapy_ssl_tls.ssl_tls import *
from scapy.layers import http

def initialise():
    scapy.sniff("eth0", store=False, prn=filter_packets)


def get_protocol_data(packet, target, *args):
    #filter_function_dict = {"http":filter_http_packet(packet, target), "ARP":filter_ARP_packet(packet, target)\
    #,"ICMP":filter_ICMP_layer(packet, target)}
    scapy_args = ["RAW", "TCP", "UDP", "ARP", "ICMP"] ## these will be checked against supplied protocols names in the optparse stage
    scapy_http_args = ["HTTPRequest", "HTTPResponse",]
    #test_args = ["http.HTTPRequest", "http.HTTPResponse"]
    if not args:
        print ("You have not supplied any target protocols, the defaults are http, ARP, and ICMP")
        for default_protocol in default_args:
            filter_function_dict[default_protocol]
    else:
        for protocol in args:
            if (protocol in scapy_args):
                if (packet.haslayer(getattr(scapy, protocol))):
                    pass
            elif (protocol in scapy_http_args):
                if (packet.haslayer(getattr(http, protocol))):
                    print("http layer check")
                    packet_summary = filter_http_packet(packet, target) ## doing the http test case first
                    display_outputs(packet_summary)


                

def display_outputs(packet_summary):
        print(packet_summary[0])
        print(packet_summary[1][0] + packet_summary[2][0] + "->" + packet_summary[1][1] + packet_summary[2][1])



def filter_ARP_packet(packet, target):
    if packet.haslayer(scapy.ARP):
        packet_type = "ARP"
        mac_source = packet[scapy.ARP].hwsrc
        mac_dest = packet[scapy.ARP].hwdst
        ip_source = packet[scapy.ARP].psrc
        ip_dest = packet[scapy.ARP].pdst
        return (mac_source, mac_dest, ip_source, ip_dest)


def filter_ICMP_layer(packet, target):
    if packet.haslayer(scapy.ICMP):
        packet_type = "ICMP"
        type_dict = {"0":"Echo Reply", "3":"Destination Unreachable", "5":"Redirect Message",\
         "8":"Echo Request", "10":"Router Solicitation", "9":"Router Advertisement", "11":"Time Exceeded"}
        message_type =  packet[scapy.ICMP].type + " " + type_dict[packet[scapy.ICMP].type]
        code = packet[scapy.ICMP].code
        return (packet_type, message_type, code)
        

def filter_http_packet(packet, target):
    #print("function call check")
    if packet.haslayer(scapy.IP):
        #print("ip layer check")
        ether_tuple = filter_ethernet_layer(packet)
        ip_tuple = filter_IP_layer(packet)
        if ((target == ip_tuple[0]) or (target == ip_tuple[1])):
            #print("target match check")
            if packet.haslayer(http.HTTPRequest):
                request_tuple = filter_http_request(packet)
                http_frame_request = (request_tuple, ip_tuple, ether_tuple)
                #print("req frame: " , http_frame_request)
                return http_frame_request
            if packet.haslayer(http.HTTPResponse):
                response_tuple = filter_http_response(packet)
                http_frame_response = (response_tuple, ip_tuple, ether_tuple)
                #print("resp frame: "  , http_frame_response)
                return http_frame_response



def filter_http_request(packet):
    packet_type = "HTTP Request"
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    method = packet[http.HTTPRequest].Method
    encoding = packet[http.HTTPRequest].Accept_Encoding
    packet[http.HTTPRequest].show()
    return (packet_type, url, method, encoding)



def filter_http_response(packet):
    packet_type = "HTTP Response"
    status = packet[http.HTTPResponse].Status_Code + " " + packet[http.HTTPResponse].Reason_Phrase
    encoding = packet[http.HTTPResponse].Content_Encoding
    date = packet[http.HTTPResponse].Date
    content_type = packet[http.HTTPResponse].Content_Type
    return (packet_type, status, encoding, date, content_type)



def filter_ethernet_layer(packet):
    source_mac = packet[scapy.Ether].src
    dest_mac = packet[scapy.Ether].dst
    return (source_mac, dest_mac)


def filter_IP_layer(packet):
    #ttl = packet[scapy.IP].ttl
    source_ip = packet[scapy.IP].src
    dest_ip = packet[scapy.IP].dst
    return (source_ip, dest_ip)

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
    get_protocol_data(packet, "192.168.0.34", "HTTPRequest", "HTTPResponse")
    #filter_tls(packet)
    #filter_http_login(packet)

initialise()
