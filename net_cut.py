#!/usr/bin/env
import netfilterqueue
import scapy.all as scapy
import subprocess
import sys
import string
import argparse


def set_iptables():
	subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])

def reset_iptables():
	subprocess.call(["iptables", "--flush"])

def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("-w", "--whitelist", nargs="+", dest="whitelist", help="Add one or more IP addresses to white list them from having their packets dropped")
	args = parser.parse_args()
	
	if args._get_kwargs()[0][1] is None:
		 parser.error("[-] no IP addresses provided for whitelist, dropping all packets in queue")
		 #sys.exit(0) this shouldn't be here
	return args


def make_queue():
	set_iptables()
	queue = netfilterqueue.NetfilterQueue()
	queue.bind(0, drop_packet)
	try:
		queue.run()
	except KeyboardInterrupt:
		print("exiting...")
		reset_iptables()
		sys.exit(0)


def set_whitelist():
	args = get_args()
	return args._get_kwargs()[0][1] 


def drop_packet(packet):

	scapy_packet = scapy.IP(packet.get_payload())
	if set_whitelist() not None:
		ip_whitelist = set_whitelist()
	if scapy_packet.haslayer(scapy.IP):
		if ((string.strip(scapy_packet[scapy.IP].src) not in ip_whitelist) and (string.strip(scapy_packet[scapy.IP].dst) not in ip_whitelist)):
			sys.stdout.write("\033[1;31m")
			print("packet dropped  src: " + scapy_packet[scapy.IP].src + " dst: " + scapy_packet[scapy.IP].dst)
			sys.stdout.write("\033[0;31m")
			packet.drop()
		else:

			sys.stdout.write("\033[1;32m")
			print("packet accepted src: " + scapy_packet[scapy.IP].src + " dst: " + scapy_packet[scapy.IP].dst) 
			sys.stdout.write("\033[1;32m")
			packet.accept()
			 

make_queue()
