#!/usr/bin/python3

from socket import *
import optparse
from threading import *


def connScan(tgtHost,tgtPort):
	try:
		sock = socket(AF_INET, SOCK_STREAM)
		sock.connect((tgtHost,tgtPort))
		banner = sock.recv(1024)
		print('\033[0;32;48m[+] Port %d/tcp is Open' % tgtPort + '\033')
		print('Open' + banner)
	except:
		#print('\033[0;31;48m[-] Port %d/tcp is Closed' % tgtPort + '\033')
		return None
	finally:
		sock.close()

def portScan(tgtHost,tgtPorts,tgtTime):
	try:
		tgtIP = gethostbyname(tgtHost)
	except:
		print('Cannot resove %s'  %tgtHost)
	try:
		tgtName = gethostbyaddr(tgtIP)
		print('\033[0;34;48m[+] Scan reslts for: ' + tgtName[0] + ' at \033' + tgtIP)
	except:
		print('\033[0;34;48m[+] Scan results for: ' + tgtIP + '\033')
	setdefaulttimeout(int(tgtTime))
	for tgtPort in tgtPorts:
		t = Thread(target=connScan, args=(tgtHost,int(tgtPort)))
		t.start()

def main():
	parser = optparse.OptionParser('\033[1;33;48m Usage: \n' + '-H <target host>\n-S <starting port>\n-E <ending port>\n-T <set default scan timeout>\n-h or --help <for help>\033')
	parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
	parser.add_option('-S', dest='sPort', type='int', default=1,help='specify target ports seperated by a comma')
	parser.add_option('-E', dest='ePort', type='int', default=10,help='specify target ports seperated by a comma')
	parser.add_option('-T', dest='tgtTime', type='string', help='specify scan timeout')
	(options, args) = parser.parse_args()
	tgtHost = options.tgtHost
	sPort = options.sPort
	ePort = options.ePort
	port_list = list(range(sPort,ePort + 1))
	tgtPort = [str(i) for i in port_list]
	tgtPorts = tgtPort#str(options.tgtPort).split(',')
	tgtTime = options.tgtTime
	if (tgtHost == None) | (tgtPorts[0] == None) | (tgtTime == None):
		print (parser.usage)
		exit(0)
	print('Pool Corps Port Scanner')
	print(60 * '-')
	portScan(tgtHost,tgtPorts,tgtTime)


if __name__ == '__main__':
	main()