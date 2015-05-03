import os
import argparse
import socket
import struct


def GetBinaryIP(IP):
	try:
		return struct.unpack("!I", socket.inet_aton(IP))[0]
   	# legal
	except socket.error:
			return 0
   	# Not legal

def PingServer(IP):
	response = os.system("ping -c 1 " + IP)
	#and then check the response...
	if response == 0:
		print '\n******* ' + IP, 'is up! *******'
		return True
	else:
		print '\n' + IP, 'is down!'
		return False

def GetStringIP(IP):
	try:
		packed_value = struct.pack('!I', IP)
		addr = socket.inet_ntoa(packed_value)
		return addr
   	#legal
	except socket.error:
		return "NULL"
	#Not legal

def CheckOpenTcpPort(IP, PORT):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect((IP, PORT))	
		s.close()
		return True
	except Exception, e:
		print('Port Closed: ', PORT)
		s.close()
    	return False

def PortScan(BinaryIP, BinaryMask):

	#Const ports to scan
	HTTP_PORT = 80
	SSH_PORT = 22
	FTP_PORT = 21
	
	NetWorkMaskToScan = (BinaryIP & BinaryMask)
	NetworkIP = GetStringIP(NetWorkMaskToScan)
	print("Subnet To Scan: " + NetworkIP)

	# Run on subnet range and check ports
	for i in range(255):
		IpToScan = NetWorkMaskToScan | i
		StringIpToScan = GetStringIP(IpToScan)
		print("Scanning ip: " + StringIpToScan)

		#Check if the machine is up
		if (PingServer(StringIpToScan) == True):
			
			#Check if the ports are open
			if(CheckOpenTcpPort(StringIpToScan,HTTP_PORT) == True):
				print('ip: ' + StringIpToScan + ' HTTP Port Is open:)')
			if(CheckOpenTcpPort(StringIpToScan,FTP_PORT) == True):
				print('ip: ' + StringIpToScan + ' FTP Port Is open:)')
			if(CheckOpenTcpPort(StringIpToScan,SSH_PORT) == True):
				print('ip: ' + StringIpToScan + ' SSH Port Is open:)')