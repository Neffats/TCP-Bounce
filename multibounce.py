from scapy.all import *
import time
from bs4 import BeautifulSoup
import requests
import re
import socket
import os
import url_retreiver


'''
The base class for all of the other sender classes.

Attributes:
	bounce_endpoints - List of IP's that will be used to bounce the packets off.
	receiver_address - IP address of the message recipient.
	receiver_port - Port that the message recipient is listening for message on.
	bounce_port - The port that will be used to bounce the packets off. Default is 443.
'''
class Sender():
	def __init__(self, receiver_address: str, receiver_message_port: int, receiver_init_port: int, bounce_endpoints: list, bounce_port=443):
		self.bounce_endpoints = bounce_endpoints
		self.receiver_address = receiver_address
		self.receiver_message_port = receiver_message_port
		self.receiver_init_port = receiver_init_port
		self.bounce_port = bounce_port


'''
This is the implementation for the "Block Sender". This send a string to the specified listener. 
This implementation of the sender will send the message in blocks or chunks of 3 characters at a time, hence the "block" name.

The blocks are constructed by:

Step 1:
	A = 0x41
	Block = 0x00000000

Step 2:
	OR 	0x00000041
		0x00000000
Block = 0x00000041

Step 3:
	Block = 0x00000041 << 2 (Shift by 2)
	Block = 0x00004100

	Jump to Step 1.

	This would be done for each of the letters in the block, except for the last letter which won't be shifted.

'''
class Block_Sender(Sender):
	def __init__(self, receiver_address: str, receiver_message_port: int, receiver_init_port: int, bounce_endpoints: list, bounce_port: int):
		Sender.__init__(self, receiver_address, receiver_message_port, receiver_init_port, bounce_endpoints, bounce_port)
		self.BLOCK_SZ = 3
		self.CHAR_MASKS = [0xFF000000, 0x00FF0000, 0x0000FF00, 0x000000FF]
		self.CONTROL_HEADERS = {'DATA': 268435456}
		self.TYPE_CODE = 0x01

	def get_receiver_address(self):
		return self.receiver_address

	def send(self, message: str):	
		message_blocks = []
		message_index = 0
		unused_endpoints = self.bounce_endpoints[:]
		used_endpoints = []

		assert(type(message) == str), "Message for Block_Sender must be a string."

		while message_index < len(message):
			new_block = self.encode_block(message[message_index:message_index + self.BLOCK_SZ])
			new_block = self.add_header(message_block=new_block, header_type='DATA')
			message_blocks.append(new_block)
			message_index += self.BLOCK_SZ

		bounce_endpoint = unused_endpoints.pop()
		message_init = self.generate_init(message, self.receiver_init_port)
		self.send_init(message_init, bounce_endpoint)
		used_endpoints.append(bounce_endpoint)
		for block in message_blocks:
			if not unused_endpoints:
				unused_endpoints = used_endpoints[:]
				used_endpoints = []
			bounce_endpoint = unused_endpoints.pop()
			block_result = self.send_block(block=block, bounce_address=bounce_endpoint)
			used_endpoints.append(bounce_endpoint)
			print(f"Block send success: {block_result}")

	def encode_block(self, letters: str) -> int:
		encoded_block = 0
		for i in range(self.BLOCK_SZ-1):
			encoded_block = int(encoded_block) | ord(letters[i])
			encoded_block = encoded_block << 8
		encoded_block = int(encoded_block) | ord(letters[-1])
		return encoded_block

	def decode_block(self, encoded_block: int) -> str:
		message_block = []
		for i in range(self.BLOCK_SZ):
			temp = encoded_block & self.CHAR_MASKS[i+1]
			shiftby = ((self.BLOCK_SZ-1)-i)*8
			message_block.append(temp >> shiftby)

		message_string = []
		[message_string.append(chr(x)) for x in message_block]
		return "".join(message_string) 

	def add_header(self, message_block: int, header_type: str) -> int:
		return message_block | self.CONTROL_HEADERS[header_type]

	def get_header(self, message_block: int) -> int:
		return (message_block & self.CHAR_MASKS[0]) >> 28

	def generate_init(self, message: str, port: int) -> int:
		msg_length = len(message)
		init_packet = 0x00000000
		init_packet = init_packet | self.TYPE_CODE
		init_packet = init_packet << 12
		init_packet = init_packet | msg_length
		init_packet = init_packet << 16
		init_packet = init_packet | port

		return init_packet

	def send_block(self, block: int, bounce_address: str) -> bool:
		print(f"Sending block: {block} ----> {self.decode_block(block)} to {bounce_address}\nHeader: {self.get_header(block)}")
		send(IP(src=self.receiver_address, dst=bounce_address)/TCP(sport=self.receiver_message_port, dport=self.bounce_port, seq=block, flags="S"))
		return True

	def send_init(self, init_data: int, bounce_address: str) -> bool:
		print(f"Sending block: {init_data}")
		send(IP(src=self.receiver_address, dst=bounce_address)/TCP(sport=self.receiver_init_port, dport=self.bounce_port, seq=init_data, flags="S"))
		return True		



if __name__ == "__main__":
	be = ['8.8.8.8', '151.101.64.81', '35.157.233.18']
	pi = ['192.168.1.121']

	bs = Block_Sender(receiver_address="192.168.1.70", receiver_message_port=3000, receiver_init_port=1337, bounce_endpoints=pi, bounce_port=22)

	innit = bs.generate_init("Hello World!", 80)

	print(innit)

	#bs.send_block(innit, '192.168.1.121')

	bs.send("Hello World!")

	#bs.send(123)