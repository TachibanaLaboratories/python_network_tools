#!/usr/bin/env

import subprocess
import argparse
import re

#get arguments from terminal command line
def get_arguments():
    #arguments are retrived from terminal
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify which interface will have its MAC address changed")
    parser.add_argument("-m", "--mac", dest="new_mac", help="Specify the new MAC address to be set")
    options = parser.parse_args()

    if (not options.interface):
        print("[-] Please specify an interface")
    elif (not options.new_mac):
        print("[-] please specify a new MAC address")
    else:   
        return options

#change mac address via ifconfig command, using subprocess
def change_mac(interface, new_mac):
    subprocess.run(["ip", "link", "set", interface, "down"])
    subprocess.run(["ip", "link", "set", interface, "address", new_mac])
    subprocess.run(["ip", "link", "set", interface, "up"])


#check current mac address
def get_current_mac(interface):
    ip_result = subprocess.check_output(["ip", "addr", "show", "dev", interface])
    mac_address_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ip_result.decode('utf-8'))
    return mac_address_result.group(0)


#compare intended mac address with current mac address
def check_mac_changed(old_mac, new_mac):
    if (old_mac == new_mac):
        print("[+] MAC has been been updated to" + new_mac)
    else:
        print("[-]" + old_mac + " has not been updated to " + new_mac)

#initialise functions
options = get_arguments()
change_mac(options.interface, options.new_mac)
current_mac = get_current_mac(options.interface)
check_mac_changed(current_mac, options.new_mac)
