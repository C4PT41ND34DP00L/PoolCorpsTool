#!/usr/bin/env python3

import subprocess
import optparse
import random

def randomMAC():
	mac = [ 0x00, 0x16, 0x3e,
		random.randint(0x00, 0x7f),
		random.randint(0x00, 0xff),
		random.randint(0x00, 0xff) ]
	return ':'.join(map(lambda x: "%02x" % x, mac))
#
#print (randomMAC())

def change_mac(interface, new_mac):
	print('[+] Chenaging MAC Address for ' + interface + ' to ' + new_mac)

	subprocess.call(['ifconfig', interface, 'down'])
	subprocess.call(['ifconfig', interface, 'hw','ether',new_mac])
	subprocess.call(['ifconfig', interface, 'up'])


parser = optparse.OptionParser()

parser.add_option('-i', '--interface', dest='interface',help='Interface to change MAC Address')
#parser.add_option('-m', '--mac',dest='new_mac',help='New MAC address')

(options, arguments) = parser.parse_args()

change_mac(options.interface,randomMAC())

