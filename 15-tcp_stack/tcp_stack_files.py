#!/usr/bin/python2

import sys
import string
import socket
from time import sleep

def server(port):
	s = socket.socket()
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		
	s.bind(('0.0.0.0', int(port)))
	s.listen(3)
		
	cs, addr = s.accept()
	print addr

	fo = open("server-output.dat", "w")
		
	while True:
		data = cs.recv(65535)
		print(type(data))
		if data:
			fo.write(data)
		else:
			break
		
	fo.close()

	s.close()


def client(ip, port):
	s = socket.socket()
	s.connect((ip, int(port)))
		
	fo = open("client-input.dat", "r")
	data = fo.read()
	s.send(data)
		
	fo.close()
		
	s.close()

if __name__ == '__main__':
	if sys.argv[1] == 'server':
		server(sys.argv[2])
	elif sys.argv[1] == 'client':
		client(sys.argv[2], sys.argv[3])
