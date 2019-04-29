from scapy.all import *
import time
from bs4 import BeautifulSoup
import binascii
import re
import socket
import os
import url_retreiver
import consts
import logging
import random


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

	def get_receiver_address(self):
		return self.receiver_address

	def send(self, message: str):	
		if type(message) != str:
			raise TypeError("Message for Block_Sender must be a string.")
		
		message_blocks = []
		message_index = 0
		unused_endpoints = self.bounce_endpoints[:]
		random.shuffle(unused_endpoints)
		used_endpoints = []

		pad_length = consts.BLOCK_SZ - (len(message) % consts.BLOCK_SZ) 

		message += (chr(0))*pad_length

		# Convert/Encode message into blocks ready to be sent.
		while message_index < len(message):	
			new_block = self.encode_block(message[message_index:message_index + consts.BLOCK_SZ])
			new_block = self.add_header(message_block=new_block, header_type='DATA')
			message_blocks.append(new_block)
			message_index += consts.BLOCK_SZ

		# Send the init packet to set up the session.
		bounce_endpoint = unused_endpoints.pop()
		message_init = self.generate_init(message, self.receiver_message_port)
		self.send_init(init_data=message_init, bounce_address=bounce_endpoint)
		used_endpoints.append(bounce_endpoint)

		time.sleep(1)

		if not unused_endpoints:
			unused_endpoints = used_endpoints[:]
			random.shuffle(unused_endpoints)
			used_endpoints = []

		# Generate and send the message CRC32 checksum.
		# Server will use this to check for errors or missing packets.
		msg_checksum = int(self.gen_crc(message))
		logging.info(f"Message checksum: {msg_checksum}")
		bounce_endpoint = unused_endpoints.pop()
		block_result = self.send_block(block=msg_checksum, bounce_address=bounce_endpoint)
		used_endpoints.append(bounce_endpoint)
		logging.info(f"Checksum sent.")

		time.sleep(0.2)
		
		# Send the message blocks to the server.
		for block in message_blocks:
			# If all endpoints have been used, refresh the list
			if not unused_endpoints:
				unused_endpoints = used_endpoints[:]
				random.shuffle(unused_endpoints)
				used_endpoints = []
			bounce_endpoint = unused_endpoints.pop()
			block_result = self.send_block(block=block, bounce_address=bounce_endpoint)
			used_endpoints.append(bounce_endpoint)
			logging.info(f"Block send success: {block_result}")
			time.sleep(0.2)
		if not unused_endpoints:
			bounce_endpoint = used_endpoints.pop()
		else:
			bounce_endpoint = unused_endpoints.pop()
		time.sleep(1)

		# Send end packet to signify the end of the message. This is how the server
		# knows that the session has ended.
		self.send_end(bounce_address=bounce_endpoint)

	# Takes a block of 3 characters.
	def encode_block(self, letters: str) -> int:
		if len(letters) > consts.BLOCK_SZ or len(letters) < consts.BLOCK_SZ:
			raise ValueError(
				f"Block of incorrect length passed to encoded_block(). Given: {len(letters)}, Want: {consts.BLOCK_SZ} Data: {letters}",)
		encoded_block = 0
		for i in range(consts.BLOCK_SZ-1):	
			encoded_block = int(encoded_block) | ord(letters[i])
			encoded_block = encoded_block << 8
		encoded_block = int(encoded_block) | ord(letters[-1])
		return encoded_block

	def decode_block(self, encoded_block: int) -> str:
		message_block = []
		for i in range(consts.BLOCK_SZ):
			temp = encoded_block & consts.CHAR_MASKS[i+1]
			shiftby = ((consts.BLOCK_SZ-1)-i)*8
			message_block.append(temp >> shiftby)

		message_string = []
		[message_string.append(chr(x)) for x in message_block]
		return "".join(message_string) 

	def add_header(self, message_block: int, header_type: str) -> int:
		return message_block | consts.CONTROL_HEADERS[header_type]

	def get_header(self, message_block: int) -> int:
		return (message_block & consts.CHAR_MASKS[0]) >> 28

	def generate_init(self, message: str, port: int) -> int:
		msg_length = len(message)
		init_packet = 0x00000000
		init_packet = init_packet | consts.TYPE_CODE
		init_packet = init_packet << 12
		init_packet = init_packet | msg_length
		init_packet = init_packet << 16
		init_packet = init_packet | port

		return init_packet

	def send_block(self, block: int, bounce_address: str) -> bool:
		logging.info(f"Sending block: {block} ----> {self.decode_block(block)} to {bounce_address}\nHeader: {self.get_header(block)}")
		send(IP(src=self.receiver_address, dst=bounce_address)/TCP(sport=self.receiver_message_port, dport=self.bounce_port, seq=block, flags="S"), verbose=False)
		return True

	def send_init(self, init_data: int, bounce_address: str) -> bool:
		logging.info(f"Sending block: {init_data}")
		send(IP(src=self.receiver_address, dst=bounce_address)/TCP(sport=self.receiver_init_port, dport=self.bounce_port, seq=init_data, flags="S"), verbose=False)
		return True	

	def send_end(self, bounce_address: str) -> bool:
		send(IP(src=self.receiver_address, dst=bounce_address)/TCP(sport=self.receiver_message_port, dport=self.bounce_port, seq=consts.CONTROL_HEADERS['END'], flags="S"), verbose=False)
		return True

	def gen_crc(self, message):
		return binascii.crc32(bytes(message, 'utf-8'))



if __name__ == "__main__":
	be = ['8.8.8.8', '151.101.64.81', '35.157.233.18']
	pi = ['192.168.1.121']

	bs = Block_Sender(receiver_address="192.168.1.70", receiver_message_port=3000, receiver_init_port=1337, bounce_endpoints=pi, bounce_port=443)

	innit = bs.generate_init("Hello World!", 80)

	print(innit)

	#bs.send_block(innit, '192.168.1.121')

	bs.send("'Twas brillig, and the slithy toves. Did gyre and gimble in the wabe: All mimsy were the borogoves, And the mome raths outgrabe.")

	#bs.send(123)