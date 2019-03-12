from scapy.all import *
import time
from bs4 import BeautifulSoup
import requests
import re
import socket
import os
import url_retreiver



class Sender():
	def __init__(self, receiver_address, receiver_port, URL_src, bounce_port=443):
		self.endpoints = url_retreiver.URL_Retreiver(URL_src)
		self.receiver_address = receiver_address
		self.receiver_port = receiver_port
		self.bounce_port = bounce_port



class Block_Sender(Sender):
	def __init__(self, receiver_address, receiver_port, URL_src, bounce_port):
		Sender.__init__(self, receiver_address, receiver_port, bounce_port, URL_src)

	def get_receiver_address(self):
		return self.receiver_address

if __name__ == "__main__":
	test = Block_Sender("10.10.10.10", 15, 443, 'https://moz.com/top500')

	print(test.get_receiver_address())