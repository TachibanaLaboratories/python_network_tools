#!/usr/bin/env
import netfilterqueue
import scapy.all as scapy
import subprocess
import sys

def set_iptables():
    subprocess.call(["iptables", "-I", "FORWARD", "-J", "NFQUEUE", "--queue-num", "0"]) # using call method for
                                                                                        # python 2.7 compatibility


def reset_iptables():
    subprocess.call(["iptables", "-flush"])


def create_queue():
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, forge_response_packet)
    queue.run()


def forge_response_packet(packet):
    try:
        print(packet.get_payload())
    except KeyboardInterrupt:
        reset_iptables()
        sys.exit(0)