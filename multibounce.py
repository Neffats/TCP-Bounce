from scapy.all import *
import time
from bs4 import BeautifulSoup
import requests
import re
import socket
import os
import url_retreiver



class Sender():
	def __init__(self, receiver_address: str, receiver_port: int, URL_src: str, bounce_port=443):
		self.endpoints = url_retreiver.URL_Retreiver(URL_src)
		self.receiver_address = receiver_address
		self.receiver_port = receiver_port
		self.bounce_port = bounce_port



class Block_Sender(Sender):
	def __init__(self, receiver_address: str, receiver_port: int, URL_src: str, bounce_port: int):
		Sender.__init__(self, receiver_address, receiver_port, bounce_port, URL_src)
		self.CHUNK_SZ = 4
		self.MASKS = [0xFF000000, 0x00FF0000, 0x0000FF00, 0x000000FF]

	def get_receiver_address(self):
		return self.receiver_address

	def send(self, message: str):
		message_chunks = []
		message_index = 0
		while message_index < len(message):
			message_chunks.append(self.encode_chunk(message[message_index:message_index + self.CHUNK_SZ]))
			message_index += self.CHUNK_SZ
		for chunk in message_chunks:
			self.send_chunk(chunk)

	def encode_chunk(self, letters: str) -> int:
		encoded = 0
		for i in range(len(letters)-1):
			encoded = int(encoded) | ord(letters[i])
			encoded = encoded << 8
		encoded = int(encoded) | ord(letters[-1])
		return encoded

	def decode_chunk(self, encoded: int) -> str:
		message_chunk = []
		for i in range(self.CHUNK_SZ):
			temp = encoded & self.MASKS[i]
			shiftby = ((self.CHUNK_SZ-1)-i)*8
			message_chunk.append(temp >> shiftby)

		message_string = []
		[message_string.append(chr(x)) for x in message_chunk]
		return "".join(message_string) 

	def send_chunk(self, chunk: int) -> bool:
		print(f"Sending chunk: {chunk} ----> {self.decode_chunk(chunk)}")
		return True


if __name__ == "__main__":
	Block_Sender("10.10.10.10", 15, 443, 'https://moz.com/top500').send("Hello World!")

