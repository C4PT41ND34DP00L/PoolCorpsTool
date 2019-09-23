#!/usr/bin/python3

import socket

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

host = '10.0.0.45'
port = 22

def portscanner(port):
	if sock.connect_ex((host,port)):
		print('Port %d is cloded' % (port))
	else:
		print('Port % d is open' % (port))

portscanner(port)