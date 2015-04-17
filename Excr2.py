import os
import argparse
import socket

def IsIpValid(IP):
	try:
   			socket.inet_aton(IP)
   			return True
   	# legal
	except socket.error:
			return False
   	# Not legal

def PingServer(IP):
	response = os.system("ping -c 1 " + IP)
	#and then check the response...
	if response == 0:
		print IP, 'is up!'
		return True
	else:
		print IP, 'is down!'
		return False

def main():
	parser = argparse.ArgumentParser(description='Get IP and subnet mask for scan.')
	parser.add_argument('-IP','--IP',action='store', help='Set your ip address. inet(3) format', default="192.168.1.1")
	parser.add_argument('-subnet','--subnet',action='store', help='Set the subnet mask to check. inet(3) format',default="255.255.255.0")

	args = parser.parse_args()
	if IsIpValid(args.IP) != True:
		print("Ip is wrong, try again")
	if IsIpValid(args.subnet) != True:
		print("Subnet is wrong, try again")

	PingServer(args.IP)


if __name__ == "__main__":
   main()

