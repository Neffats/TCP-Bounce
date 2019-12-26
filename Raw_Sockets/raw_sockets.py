from ctypes import *
import multiprocessing
import os
import socket
import struct
import threading

class IP(Structure):
	_fields_ = [
		("ihl", c_ubyte, 4),
		("version", c_ubyte, 4),
		("tos", c_ubyte),
		("len", c_ushort),
		("id", c_ushort),
		("offset", c_ushort),
		("ttl", c_ubyte),
		("protocol_num", c_ubyte),
		("sum", c_ushort),
		("src", c_ulong),
		("dst", c_ulong)
	]

	def __new__(self, socket_buffer=None):
		return self.from_buffer_copy(socket_buffer)

	def __init__(self, socket_buffer=None):
		self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

		# Unpack the ip addresses from the IP header.
		self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
		self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

		try:
			self.protocol = self.protocol_map[self.protocol_num]
		except:
			self.protocol = str(self.protocol_num)


class TCP(Structure):
	_fields_ = [
		("sport", c_ushort),
		("dport", c_ushort),
		("seq", c_ulong),
		("ack", c_ulong),
		("data_offset", c_ubyte),
		("flags", c_ubyte),
		("window_size", c_ushort),
		("checksum", c_ushort),
		("urgent_ptr", c_ushort)
	]

	def __new__(self, socket_buffer=None):
		return self.from_buffer_copy(socket_buffer)

	def __init__(self, socket_buffer=None ):
		# Need to change the endianness of the values for them to be correct.
		self.src_port = socket.htons(self.sport)
		self.dst_port = socket.htons(self.dport)

		self.sequence = socket.htonl(self.seq)
		self.acknowledge = socket.htonl(self.ack)


class Filter():
	def __init__(self, port: int) -> None:
		self.port = port



class Socker(threading.Thread):
	def __init__(self, bind_ip: str) -> None:
		self.bind_ip = bind_ip
		# Used to recieve new filters from the main process.
		self.filter_queue = multiprocessing.Queue()
		# Used to send matches to the filters back to the main process.
		self.results_queue = multiprocessing.Queue()

		# Contains a list of ports that we're looking for.
		self.filters = []

	def setup_socket(self) -> None:
		if os.name == "nt":
			socket_protocol = socket.IPPROTO_IP
		else:
			socket_protocol = socket.IPPROTO_ICMP

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

		self.sock.bind((bind_ip, 0))
		self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

		if os.name == "nt":
			self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

	def run(self) -> None:
		while True:
			raw_buffer = sniffer.recvfrom(65565)[0]

			ip_header = IP(raw_buffer[0:20])

			if ip_header.protocol == "TCP":
				tcp_header = TCP(raw_buffer[20:40])
				print(f"Protocol: {ip_header.protocol} {ip_header.src_address}:{tcp_header.src_port} -> {ip_header.dst_address}:{tcp_header.dst_port}: ({tcp_header.sequence}/{tcp_header.acknowledge})")


if __name__ == "__main__":
	if os.name == "nt":
		socket_protocol = socket.IPPROTO_IP
	else:
		socket_protocol = socket.IPPROTO_ICMP

	sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

	sniffer.bind(("192.168.1.70", 0))
	sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	if os.name == "nt":
		sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

	try:
		while True:
			raw_buffer = sniffer.recvfrom(65565)[0]

			ip_header = IP(raw_buffer[0:20])

			if ip_header.protocol == "TCP":
				tcp_header = TCP(raw_buffer[20:40])
				if ip_header.src_address != "192.168.1.70":
					print(f"Protocol: {ip_header.protocol} {ip_header.src_address}:{tcp_header.src_port} -> {ip_header.dst_address}:{tcp_header.dst_port}: ({tcp_header.sequence}/{tcp_header.acknowledge})")

	except KeyboardInterrupt:
		if os.name == "nt":
			sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)