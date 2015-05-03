import os
import argparse
import socket
import struct

from DnsAmplification import DnsAmplificationAttack
from SynFlood import SynFloodAttack

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
def main():

	# DnsAmplificationAttack('192.168.1.14', 1111, '8.8.8.8', 53, "www.ynet.co.il")
	SynFloodAttack('192.168.1.14','192.168.1.1')
	HTTP_PORT = 80
	SSH_PORT = 22
	FTP_PORT = 21
	parser = argparse.ArgumentParser(description='Get IP and subnet mask for scan.')
	parser.add_argument('-IP','--IP',action='store', help='Set your ip address. inet(3) format', default="192.168.1.1")
	parser.add_argument('-subnet','--subnet',action='store', help='We support only 255.255.255.0 in this version',default="255.255.255.0")

	args = parser.parse_args()
	BinaryIP = GetBinaryIP(args.IP)
	BinaryMask = GetBinaryIP(args.subnet)
	if BinaryIP == 0:
		print("Ip is wrong, try again")
		return
	if (BinaryMask == 0 or args.subnet != '255.255.255.0'):
		print("Subnet is wrong, try again")
		return
	NetWorkMaskToScan = (BinaryIP & BinaryMask)
	NetworkIP = GetStringIP(NetWorkMaskToScan)
	print("Subnet To Scan: " + NetworkIP)

	for i in range(255):
		IpToScan = NetWorkMaskToScan | i
		StringIpToScan = GetStringIP(IpToScan)
		print("Scanning ip: " + StringIpToScan)
		if (PingServer(StringIpToScan) == True):
			if(CheckOpenTcpPort(StringIpToScan,HTTP_PORT) == True):
				print('ip: ' + StringIpToScan + ' HTTP Port Is open:)')
			if(CheckOpenTcpPort(StringIpToScan,FTP_PORT) == True):
				print('ip: ' + StringIpToScan + ' FTP Port Is open:)')
			if(CheckOpenTcpPort(StringIpToScan,SSH_PORT) == True):
				print('ip: ' + StringIpToScan + ' SSH Port Is open:)')

if __name__ == "__main__":
   main()

