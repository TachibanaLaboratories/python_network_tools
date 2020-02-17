import requests, re, urlparse


def get_requests(url):
	try:
		return requests.get("http://" + url)
		print(get_response)
	except requests.exceptions.ConnectionError:
		print("Connection error")
		pass


def extract_links_from(target_url):
	response = get_requests(target_url)
	return re.findall('(?:href=")(.*?)"', response.content)

target_url = "192.168.1.101/mutillidae/"
target_links = []

def crawl(target_url, depth):
	depth += 1
	global target_links
	href_links = extract_links_from(target_url)
	for link in href_links:
		link = urlparse.urljoin(target_url, link) # converts relative URLs to proper URLs
		if "#" in link:
			link = link.split("#")[0]
		if target_url in link and link not in target_links:
			target_links.append(link)
			print(depth)
			print(link)
			crawl(link, depth)

crawl(target_url, -1)