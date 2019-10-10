#!/usr/bin/env
import scapy.all as scapy
#from scapy_ssl_tls.ssl_tls import *
from scapy.layers import http
import sys
import linecache







class TCPStream(object):
	""" This class handles TCP streams and the membership of packets in those streams"""
	def __init__(self, stack_timeout):
		assert type(stack_timeout) == type(0) ## type checking input as int
		
		self._http_request_tcp_stack = [] # I guess I should define some sort of max size

		if not stack_timeout == None:
			self._tcp_stack_timeout = stack_timeout
		else:
			self._tcp_stack_timeout = 0 # how long/ how many operations until stream is popped off stack, default is never



	def filter_TCP_reponse(packet):
		seq = packet[scapy.TCP].seq
		ack = packet[scapy.TCP].ack
		src_port = packet[scapy.TCP].sport
		dest_port = packet[scapy.TCP].dport
		tcp_response_values = (seq, ack, src_port, dest_port)
		return tcp_response_values

	def check_tcp_stream_membership(packet):
		global check_tcp_stream_membership
		# first check ports to eliminate cases, then make a list of all streams with matching ports
		# then do that sort algo where you keep splitting a list by inequality
		

	def set_stack(tcp_layer):
		pass
		# new computers have lots of ram, but I might as well set a logical limit here
		# will need the check method to work
		# the trivial first case is when http_request_tcp_stack is empty, so we put our first stream straight in


	def set_tcp_stack_timeout(self, timout):
		pass


class PacketSniffer(object):

	def __init__(self, target, *args): # args are target protocols
		self._my_mac = scapy.Ether().src
		self._mac_ip = scapy.IP().src
		self._target_ip = target
		self._target_protocols = args
		self._is_target_up = self.is_target_up() 

	# stolen from here: https://stackoverflow.com/questions/14519177/python-exception-handling-line-number

	def is_target_up(self):
		pass

	def print_exception(self):
		exc_type, exc_obj, tb = sys.exc_info()
		f = tb.tb_frame
		lineno = tb.tb_lineno
		filename = f.f_code.co_filename
		linecache.checkcache(filename)
		line = linecache.getline(filename, lineno, f.f_globals)
		print('EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj))


	def get_my_if(self):
		return (self._my_ip, self._my_mac)

	def get_target_ip(self):
		return self._target_ip

	def get_target_protocols(self):
		return self._target_protocols


	#def pass_arguments(packet):
		#get_protocol_data(packet, "192.168.0.34", "HTTPRequest", "HTTPResponse")
		

	def get_protocol_data(self, packet):
		try:
			target = self.get_target_ip()
			args = self.get_target_protocols()

			#filter_function_dict = {"http":filter_http_packet(packet, target), "ARP":filter_ARP_packet(packet, target)\
			#,"ICMP":filter_ICMP_layer(packet, target)}
			scapy_args = ["RAW", "TCP", "UDP", "ARP", "ICMP", "Raw"] ## these will be checked against supplied protocols names in the optparse stage
			scapy_http_args = ["HTTPRequest", "HTTPResponse",]
			#test_args = ["http.HTTPRequest", "http.HTTPResponse"]
			if (not args or args == None):
				print ("You have not supplied any target protocols, the defaults are http, TCP, and ICMP")
				for default_protocol in default_args:
					filter_function_dict[default_protocol]
			else:
				for protocol in args:
					if (protocol in scapy_args):
						if (packet.haslayer(getattr(scapy, protocol))):
							pass
					elif (protocol in scapy_http_args):
						if (packet.haslayer(getattr(http, protocol))):
							#print("http layer check")
							packet_summary = self.filter_http_packet(packet, target) ## doing the http test case first
							if packet_summary is not None:
								self.display_outputs(packet_summary, protocol)
		except:
			self.print_exception()


	def sniff(self):
		scapy.sniff("eth0", store=False, prn=self.get_protocol_data) #prn=function
				

	def display_outputs(self, packet_summary, protocol):
		if (protocol == "HTTPRequest" or protocol == "HTTPResponse"):
			try:
				
				if len(packet_summary) == 3:
					print('\033[1;30;42m')
	 
					print(str(packet_summary[0]).strip('()'))
					print("| " + packet_summary[1][0] + " | " + packet_summary[2][0] + " | " + " --> " + " | " + packet_summary[1][1] + " | " + packet_summary[2][1] + " | ")
				elif (len(packet_summary) == 4):
					pass
					#print("LOGIN DEETS")
					#print(packet_summary[3])
				print('\033[1;30;40m')
				print("----------------------------------------------------------------------------------------------")
			except TypeError:
				print("Something has gone wrong, packet summary contains NoneType where it should be a tuple")
				print("PACKET SUMMARY")
				print(packet_summary)
				print("")
				print("continuing...")
				self.print_exception()
				




	def filter_ARP_packet(packet, target):
		if packet.haslayer(self, scapy.ARP):
			packet_type = "ARP"
			mac_source = packet[scapy.ARP].hwsrc
			mac_dest = packet[scapy.ARP].hwdst
			ip_source = packet[scapy.ARP].psrc
			ip_dest = packet[scapy.ARP].pdst
			return (self, mac_source, mac_dest, ip_source, ip_dest)


	def filter_ICMP_layer(self, packet, target):
		if packet.haslayer(scapy.ICMP):
			packet_type = "ICMP"
			type_dict = {"0":"Echo Reply", "3":"Destination Unreachable", "5":"Redirect Message",\
			 "8":"Echo Request", "10":"Router Solicitation", "9":"Router Advertisement", "11":"Time Exceeded"}
			message_type =  packet[scapy.ICMP].type + " " + type_dict[packet[scapy.ICMP].type]
			code = packet[scapy.ICMP].code
			return (packet_type, message_type, code)
			

	def filter_http_packet(self, packet, target):
		#print("function call check")
		

		if (packet.haslayer(scapy.IP) and packet.haslayer(scapy.Ether)):
			#print("ip layer check")
			#special_checks(packet)
			ether_tuple = self.filter_ethernet_layer(packet)
			ip_tuple = self.filter_IP_layer(packet)
			if ((target == ip_tuple[0]) or (target == ip_tuple[1])):
				#print("target match check")
				#packet.show()
				if packet.haslayer(http.HTTPRequest):
					request_tuple = self.filter_http_request(packet)
					http_request_packets = (request_tuple, ip_tuple, ether_tuple)
					#print("req frame: " , http_frame_request)
					return http_request_packets
				if packet.haslayer(http.HTTPResponse):
					response_tuple = self.filter_http_response(packet)
					http_response_packets = (response_tuple, ip_tuple, ether_tuple)
					#print("resp frame: "  , http_frame_response)
					return http_response_packets


	def special_checks(self, packet):
		self.filter_http_login(packet)
		self.filter_code_injection(packet)

	

	def filter_http_request(self, packet):
		packet_type = "HTTP Request"
		url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
		method = packet[http.HTTPRequest].Method
		encoding = packet[http.HTTPRequest].Accept_Encoding
		#packet[http.HTTPRequest].show()
		return (packet_type, url, method, encoding)


	def filter_http_response(self, packet):
		packet_type = "HTTP Response"
		status = packet[http.HTTPResponse].Status_Code + " " + packet[http.HTTPResponse].Reason_Phrase
		encoding = packet[http.HTTPResponse].Content_Encoding
		date = packet[http.HTTPResponse].Date
		content_type = packet[http.HTTPResponse].Content_Type
		return (packet_type, status, encoding, date, content_type)



	def filter_ethernet_layer(self, packet):
		source_mac = packet[scapy.Ether].src
		dest_mac = packet[scapy.Ether].dst
		return (source_mac, dest_mac)


	def filter_IP_layer(self, packet):
		#ttl = packet[scapy.IP].ttl
		source_ip = packet[scapy.IP].src
		dest_ip = packet[scapy.IP].dst
		return (source_ip, dest_ip)



class AttackMapper(object):
	def __init__(self, packet, target, tcp_stream, mode):
		self._mode = mode ## Two useful modes will be: 1. you are the attacker, you want to see exactly what is happening over the network\
								## 2. you are just observing a network and want to detect suspicious activity

	def mode_controller(self, mode):
		filter_code_injection()
		filter_http_login()

	def is_suspected_under_attack(self):
		pass

	def is_suspected_under_attack_by(self):
		pass

	def suspected_attack_surface(self):
		pass

	def suspected_attack_method(self):
		pass

	def suspected_payloads(self):
		pass

	def suspected_target_response(self):
		pass



	###################CODE INJECTION #############################
	def filter_code_injection(packet):
		if packet.haslayer(http.HTTPRequest):
			filter_code_injection_request(packet)
		elif packet.haslayer(http.HTTPResponse):
			filter_code_injection_response(packet)



	def filter_code_injection_request(packet):
		if packet[http.HTTPRequest].Set_Encoding == "":
			print("\033[1;30;41")
			print("Modified HTTP request, the following HTTP RESPONSE may be a code injection attack")

	def filter_code_injection_response(packet):
		pass


	###################LOGIN SNIFFING #############################

		

	def filter_http_login(packet):
		print("check raw")
		#packet.show()
		if packet.haslayer(scapy.Raw) and packet.haslayer(http.HTTPRequest):
			print("has raw layer")
			return extract_login(packet[scapy.Raw].load)

	def extract_login(login_packet):
		login_identifier = ["user", "username", "user_name", "login", "email", "pass", "password", "pword"]
		for identifier in login_identifier:
			if identifier in login_packet:
				#return ("[+] possible username/ password: " , login_packet)
				print('\033[1;32;46m')
				print("[+] possible username/ password: " + login_packet)
				break


def initialise():
	target = "192.168.0.20"
	packet_sniffer = PacketSniffer(target, "HTTPRequest", "HTTPResponse")
	packet_sniffer.sniff()

initialise()


	


