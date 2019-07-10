#!/usr/bin/env

import subprocess
import argparse
import re

#check current mac address
def get_current_mac(interface):
    ip_result = subprocess.check_output(["ip", "addr", "show", "dev", interface])
    mac_address_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ip_result.decode('utf-8'))
    return mac_address_result.group(0)


#compare intended mac address with current mac address
def check_mac_changed(old_mac, new_mac):
    if (old_mac == new_mac):
        print("[+] MAC has been been updated to " + new_mac)
    else:
        print("[-]" + old_mac + " has not been updated to " + new_mac)


new_mac = "68:f7:28:7a:6f:a5"
old_mac = get_current_mac("eth0")
check_mac_changed(old_mac, new_mac)