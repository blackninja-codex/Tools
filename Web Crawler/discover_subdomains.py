import requests
import re

def request(url):
	try:
		return requests.get("https://" + url)
	except requests.exceptions.ConnectionError:
		pass

target_url = "google.com"

with open("location_to_subdomain.txt","r") as wordlist:
	print("Discovering Subdomain")
	
	for line in wordlist:
		word = line.strip()
		test_url = word + "." + target_url
		response = request(test_url)
		if response:
			print("Discovered Subdomain -->" + test_url)