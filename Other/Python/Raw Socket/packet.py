import socket
import struct
import sys

# https://www.cybrary.it/0p3n/raw-sockets-python-syn-tcp-scan/
def checksum(msg):
	s = 0
	# loop taking 2 characters at a time
	for i in range(0, len(msg), 2):
		print(type(msg[i]))
		w = (msg[i] << 8) + (msg[i+1] )
		s = s + w

	s = (s>>16) + (s & 0xffff);
	s = s + (s >> 16);
	#complement and mask to 4 byte short
	s = ~s & 0xffff

	return s


try:
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error as msg:
	print(msg)
	sys.exit()


# tell kernel not to put in headers, since we are providing it
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)	


# now start constructing the packet
packet = '';

source_ip = '192.168.1.70'
dest_ip = "216.58.204.4"


# ip header fields
ihl = 5
version = 4
tos = 0
tot_len = 20
id = 54321  #Id of this packet
frag_off = 0
ttl = 255
protocol = socket.IPPROTO_TCP
check = 10  # python seems to correctly fill the checksum
saddr = socket.inet_aton ( source_ip )  #Spoof the source ip address if you want to
daddr = socket.inet_aton ( dest_ip )

ihl_version = (version << 4) + ihl

# the ! in the pack format string means network order
ip_header = struct.pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)


# tcp header fields
source = 12345  # source port
dest = 5555  # destination port
seq = 0
ack_seq = 0
doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
#tcp flags
fin = 0
syn = 1
rst = 0
psh = 0
ack = 0
urg = 0
window = socket.htons (5840)


#maximum allowed window size
check = 0
urg_ptr = 0

offset_res = (doff << 4) + 0
tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)

# the ! in the pack format string means network order
tcp_header = struct.pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, check, urg_ptr)


source_address = socket.inet_aton( source_ip )
dest_address = socket.inet_aton(dest_ip)
placeholder = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_header)

psh = struct.pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);

psh = psh + tcp_header;

tcp_checksum = checksum(psh)

tcp_header = struct.pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)


packet = ip_header + tcp_header

s.sendto(packet, ('10.0.0.0', 0)) 