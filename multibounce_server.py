from scapy.all import *
import time
import os
import threading
import queue
import logging


class Bounce_Server():
	def __init__(self, listen_port: int):
		self.listen_port = listen_port

		self.BLOCK_SZ = 3
		self.CHAR_MASKS = [0xFF000000, 0x00FF0000, 0x0000FF00, 0x000000FF]
		self.INIT_MASKS = {'MSG_LEN': 0x0FFF0000, 'PORT': 0x0000FFFF}
		self.CONTROL_HEADERS = {'DATA': 268435456}
		self.TYPE_CODE = 0x01

	def run(self):
		self.handler_thread = threading.Thread(target=self.run_handling_thread)
		self.handler_thread.daemon = True
		self.handler_thread.start()

	def run_handling_thread(self):
		self.the_end = threading.Event()

		logging.debug("Starting server on.....")
		logging.debug(f"Listening on port {self.listen_port}")

		while not self.the_end.is_set():
			self.main_listener_thread_end = threading.Event()

			self.main_listener_thread = threading.Thread(target=self.run_main_listener_thread())
			self.main_listener_thread.daemon = True
			self.main_listener_thread.start()

		self.main_listener_thread.join()

	def run_main_listener_thread(self):
		logging.debug("Main listener....")
		while not self.main_listener_thread_end.is_set() or not self.the_end.is_set():
			sniff(filter=f'tcp and dst port {self.listen_port}', prn=self.handle_innit)

	def handle_innit(self, packet):
		logging.debug("Received innit packet....")
		payload = int(packet[TCP].ack - 1)

		logging.debug("Ack number received: %d....", packet[TCP].ack)
		innit_data = self.decode_innit(payload)
		logging.debug("Innit: TYPE: %d    LEN: %d     PORT: %d", innit_data['type'], innit_data['msg_length'], innit_data['port'])


	def run_session_listener_thread(self, port: int, length: int):
		logging.debug("Session listener thread started on port %d.....", port)
		sniff(filter=f'tcp and dst port {port}', prn=self.handle_message_data, count=length)

	def handle_message_data(self, packet):
		payload = int(packet[TCP].ack - 1)
		logging.debug("Message data received....")
		message_block = self.decode_block(payload)
		logging.debug("Message: %s", message_block)

	def decode_block(self, encoded_block: int) -> str:
		message_block = []
		for i in range(self.BLOCK_SZ):
			temp = encoded_block & self.CHAR_MASKS[i+1]
			shiftby = ((self.BLOCK_SZ-1)-i)*8
			message_block.append(temp >> shiftby)

		message_string = []
		[message_string.append(chr(x)) for x in message_block]
		return "".join(message_string) 	

	def decode_innit(self, payload: int):
		innit_data = {}
		innit_data['type'] = payload >> 28
		innit_data['msg_length'] = (payload & self.INIT_MASKS['MSG_LEN']) >> 16
		innit_data['port'] = payload & self.INIT_MASKS['PORT']
		return innit_data




if __name__ == '__main__':
	logging.getLogger().setLevel(logging.DEBUG)
	server = Bounce_Server(listen_port=1337)
	server.run()

	time.sleep(500)