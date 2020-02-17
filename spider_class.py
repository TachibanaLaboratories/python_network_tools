import requests, re, urlparse

class Spider():
	def __init__(self, target_url):
		self._target_url = target_url
		self._target_links = []
		self._depth = -1


	def get_requests(self, target_url):
		try:
			return requests.get("http://" + target_url)
			print(get_response)
		except requests.exceptions.ConnectionError:
			print("Connection error")
			pass


	def extract_links_from(self, target_url):
		response = self.get_requests(target_url)
		return re.findall('(?:href=")(.*?)"', response.content)


	def crawl(self, target_url, depth):
		depth += 1
		href_links = self.extract_links_from(target_url)
		else:
			for link in href_links:
				link = urlparse.urljoin(self._target_url, link) # converts relative URLs to proper URLs
				if "#" in link:
					link = link.split("#")[0]
				if self._target_url in link and link not in self._target_links:
					self._target_links.append(link)
					print(depth)
					print(link)
					self.crawl(link, depth)

	def run_crawl(self):
		self.crawl(self._target_url, self._depth)


target_url = "192.168.1.101/mutillidae/"
spider = Spider(target_url)
spider.run_crawl()