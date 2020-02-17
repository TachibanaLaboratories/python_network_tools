import requests


def get_requests(url):
	try:
		return requests.get("http://" + url)
		print(get_response)
	except requests.exceptions.ConnectionError:
		print("Connection error")
		pass


def run_wordlist_subdomain(target_url):
	'''
	Performs a search for subdomains of a given URL from a provided wordlist
	'''
	with open("/root/Documents/python_network_tools_repo/wordlists/subdomains-wordlist.txt") as wordlist_file:
		for line in wordlist_file:
			word = line.strip()
			test_url = word + "." + target_url
			response = get_requests(test_url)
			if response:
				print("[+] Discovered subdomain: " + test_url)

def run_wordlist_directories(target_url):
	'''
	Performs a search for directories of a given URL from a provided wordlist
	'''
	with open("/root/Documents/python_network_tools_repo/wordlists/files-and-dirs-wordlist.txt") as wordlist_file:
		for line in wordlist_file:
			word = line.strip()
			test_url = target_url + "/" + word
			response = get_requests(test_url)
			if response:
				print("[+] Discovered directory: " + test_url)
				# spider directory from here, although this will likely result in a lot of overlap



run_wordlist_directories("192.168.1.101/mutillidae")


