#! /usr/bin/env python3

import subprocess
from scapy.all import *

def mutate(payload):
	try:
		cmd = "/Users/sokeefe/Projects/learning/radamsa/bin/radamsa -n 1 -"
		ps = subprocess.Popen(cmd,shell=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
		mutated = ps.communicate(payload)[0]
	except Exception as e:
		print("Could not execute 'radamsa'." + str(e))
		sys.exit(1)

	return mutated

def check_process():
	try:
		cmd = "ps aux | grep \"./cli -c server.crt -k server.key -vv 0.0.0.0 4433\" | grep -v \"grep\""
		ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
		output = ps.communicate()[0]		
		if len(output) == 0:
			print("quicly server has stopped running. Stopping fuzzing now.")
			sys.exit(0)
	except Exception as e:
		print("Could not get process information for quicly server")

if __name__ == "__main__":

	while(True):
		c=rdpcap("packet.pcapng")
		loaded = c[0][Raw].load
		new_loaded = mutate(bytes(loaded[0:])) 
		c[0][Raw].load = new_loaded 

		try:
			record_mutated = open("mutated_packet", "wb")
			record_mutated.write(new_loaded)
			record_mutated.close()
		except Exception as e:
			print("Could not write mutated packet data to record file, named: mutated_packet. Error was: " + str(e))
			sys.exit(0)

		try:
			sendp(c[0], iface="lo0")
			check_process()
		except Exception as e:
			print("Error sending packet to server")
