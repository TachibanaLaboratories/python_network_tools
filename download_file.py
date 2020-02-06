import requests

"""
Stealing passwords
Lives in /var/www/html for the apache2 web server
"""


def download(url):
	get_response = requests.get(url)
	file_name = url.split("/")[-1]
	with open(file_name, "wb") as out_file:
		#executes while file open
		out_file.write(get_response.content)

download("https://i.4cdn.org/toy/1580910296259.jpg")