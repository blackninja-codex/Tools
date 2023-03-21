import requests

def request(url):
	try:
		return requests.get("http://" + url)
	except requests.exceptions.ConnectionError:
		pass

path=[]

def dirdiscover(url):
	with open("common_dir.txt","r") as wordlist_file:
		for line in wordlist_file:
			word = line.strip()
			test_url = url + "/" + word
			response = request(test_url)
			if response :
				print "[+] Discovered URL ----> " + test_url
				path.append(word)

url="192.168.44.101/mutillidae"
dirdiscover(url)
	
for paths in path:
	dirdiscover(url+"/"+ paths)

