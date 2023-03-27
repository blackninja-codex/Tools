import sys
import socket
from datetime import datetime
if len(sys.argv) == 2:
	target = socket.gethostbyname(sys.argv[1])
else:
	print("Invalid amount of Argument")
print("Scanning Target: " + target)
print("Scanning started at:" + str(datetime.now()))
try:
	for port in range(1,65535):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		socket.setdefaulttimeout(1)
		result = s.connect_ex((target,port))
		if result ==0:
			print("Port {} is open".format(port))
		s.close()
except Exception:
		print("\nError!Exiting Program!")
		sys.exit()