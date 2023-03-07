import re
import subprocess
import argparse

def get_arguments():
	parser=argparse.ArgumentParser()
	parser.add_option("-i","--interface",dest="interface",help="Interface to change its mac address")
	parser.add_option("-m","--mac",dest="new_mac",help="New Mac address")
	options=parser.parse_args()
	if not options.interface:
		parser.error("please specify an interface")
	if not options.new_mac:
		parser.error("please specify a new mac")
	return options

def change_mac(interface,new_mac):
	print("Changing Mac address for "+interface+"to "+new_mac)
	subprocess.call(["ifconfig",interface,"down"])
	subprocess.call(["ifconfig",interface,"hw","ether",new_mac])
	subprocess.call(["ifconfig",interface,"up"])

def get_current_mac(interface):
	ifconfig_result=subprocess.check_output(["ifconfig",interface])
	search_result=re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",ifconfig_result)
	if search_result:
		return search_result.group(0)
	else:
		print("Could not read mac address")

options=get_arguments()
current_mac=get_current_mac(options.interface)
print("Current mac"+str(current_mac))
change_mac(options.interface,options.new_mac)
if current_mac==options.new_mac:
	print("Mac address successfully changes to "+current_mac)
else:
	print("Mac address did not get change")
