import requests
import re
import urlparse

def request(url):
	try:
		return requests.get("https://" + url)
	except requests.exceptions.ConnectionError:
		pass

target_url = "google.com"
target_links = []

def extract_links_from(url):
	response = requests.get(url)
	return re.findall('(?Lhref=")(.*?)"',response.content)

def crawl(url):

	href_links = extract_links_from(url)

	for link in href_links:
		link = urlparse.urljoin(url, link)

		if "#" in link:
			link = link.split("#"[0])

		if target_url in link and link not in target_links:
			target_links.append(link)
			print(link)
			
			crawl(link)

print("Discovering All Directories")
crawl(target_url)

