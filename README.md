# python_network_tools

A collection of tools I have been creating to learn ethical penetration testing in preparation for the OSCP. These tools are presently simple and unsuitable for much beyond learning some important concepts about networking and the OSI model, but over time I will refine them as I put them to use in my study.

Disclaimer:

While these tools are simple (and kind of unimpressive), if used improperly they can be damaging to a network, and they can violate the privacy of others. This is mostly with respect to arp_spoofer.py, as it has the capacity to route all traffic on the same subnet through the network device on the machine you are running it on. Using this in conjuction with net_cut.py will drop all packets that you have intercepted, for IP addresses that you have not whitelisted.

Be responsible and ask for permission before you use these tools on anything that is not your own (and no the concept of ownership in this situation should not be subject to some esoteric personal philosphy).

Licensing:

Everything here is free open source software under GNU General Public License Version 3.



Contents:

arp_spoofer.py : this technique is commonly used to facilitate a "man in the middle". In simple terms, you broadcast ARP packets that tell the router that you are another device on the network, while telling that device that you are the router. The result is that you become "the man in the middle", and all traffic that would normally pass between that device and the router, passes through you as an intermediary


Tools that depend on arp_spoofer.py:

code_injector.py : modifies a http request such that its response will not be gzip encoded, then inserts Javascript code into the response. This tool will only affect the recipient's web browser and not the website that is being used. 

dns_spoofer.py : intercepts DNS resource record response packets 

file_injector.py

net_cut.py

packet_sniffer.py


Standalone tools:

network_scanner.py

mac_changer.py


NOTE: These tools only work against http, not https