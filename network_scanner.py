import scapy.all as scapy
import argparse

# def scan(ip):
# 	scapy.arping(ip)
# scan("ip_here")

def get_arguments():
	parser=argparse.ArgumentParser()
	parser.add_argument("-t","--target",dest="target",help="provide target ip")
	options=parser.parse_args()
	return options

def scan(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	answered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]

	clients_list = []
	for element in answered_list :
		client_dict = {"ip":element[1].psrc, "mac": element[1].hwsrc}
		clients_list.append(client_dict)
	return clients_list

def print_result(result_list):
	print("IP\t\t\tMAC Address\n--------------------------")
	for client in result_list:
		print(client["ip"] + "\t\t" + client["mac"])

option=get_arguments()
scan_result = scan(option.target)
print_result(scan_result) 