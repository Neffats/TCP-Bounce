import logging
from scapy.all import *
import time
import os
import threading
import queue
import consts
import keyboard


class Server():
	def __init__(self, listen_port: int) -> None:
		self.listen_port = listen_port
		self.reciever_queue = queue.Queue()
		self.end = False

	def run(self, handler) -> None:
		logging.debug("Starting main listener thread....")
		self.main_listener = MainListener(listen_port=self.listen_port, root_queue=self.reciever_queue)
		self.main_listener.daemon = True
		self.main_listener.start()

		while not self.end:
			if keyboard.is_pressed('q'):
				print("Goodbye.....")
				self.kill()
				self.end = True
				break
			try:
				msg = self.reciever_queue.get_nowait()
				print(msg)
				handler(msg)
				
			except queue.Empty:
				continue


		#self.main_listener.join()

	def kill(self):
		self.main_listener.kill()


class MainListener(threading.Thread):
	def __init__(self, listen_port: int, root_queue: queue.Queue) -> None:
		threading.Thread.__init__(self)
		self.listen_port = listen_port
		self.root_th_queue = root_queue
		self.reciever_queue = queue.Queue()
		self.end_signal = threading.Event()
		self.sessions = []

	def run(self) -> None:
		logging.debug(f"Main listener thread started on port {self.listen_port}....")
		while not self.end_signal.is_set():
			sniff(filter=f'tcp and dst port {self.listen_port}', prn=self.handle_packet)

	def handle_packet(self, packet) -> None:
		logging.debug(f"Received packet from {packet[IP].src}")
		payload = self.decode_init(int(packet[TCP].ack - 1))
		self.send_RST(address=packet[IP].src, port=packet[TCP].sport)
		self.start_session(payload)

	def decode_init(self, payload: int) -> dict:
		init_data = {}
		init_data['type'] = consts.TYPE_CODES[payload >> 28]
		init_data['msg_length'] = (payload & consts.INIT_MASKS['MSG_LEN']) >> 16
		init_data['port'] = payload & consts.INIT_MASKS['PORT']
		return init_data

	def start_session(self, parameters: dict) -> None:
		try:
			new_session = SessionCreator().create_session(
				listen_port=parameters['port'], 
				message_length=parameters['msg_length'], 
				root_th_queue=self.root_th_queue, 
				parent_th_queue=self.reciever_queue, 
				listener_type=parameters['type'])
		except:
			return
		new_session.daemon = True
		new_session.start()

		self.sessions.append(new_session)

	def send_RST(self, address: str, port: int) -> None:
		send(IP(dst=address)/TCP(dport=port, flags="R"), verbose=False)

	def kill(self) -> None:
		# Kill self
		self.end_signal.set()
		# Kill children
		[sess.kill() for sess in self.sessions]


class SessionCreator():
	def create_session(self, 
			listen_port: int, 
			message_length: int, 
			root_th_queue: queue.Queue, 
			parent_th_queue: queue.Queue, 
			listener_type: str):

		if listener_type == 'BLOCK':
			return BlockSessionListener(listen_port=listen_port, 
										message_length=message_length, 
										root_th_queue=root_th_queue, 
										parent_th_queue=parent_th_queue)
		else:
			raise ValueError(listener_type)


class BlockSessionListener(threading.Thread):
	def __init__(self, 
		listen_port: int, 
		message_length: int, 
		root_th_queue: queue.Queue, 
		parent_th_queue: queue.Queue) -> None:

		threading.Thread.__init__(self)
		self.listen_port = listen_port
		self.message_length = message_length
		self.root_th_queue = root_th_queue
		self.parent_th_queue = parent_th_queue

		self.comms_queue = queue.Queue()


	def run(self) -> None:
		self.listen_th_end = threading.Event()
		self.process_th_end = threading.Event()

		logging.debug("Starting session listener thread.....")
		self.listen_th = threading.Thread(target=self.start_listen_th)
		self.listen_th.daemon = True
		self.listen_th.start()

		logging.debug("Starting session processor thread.....")
		self.process_th = threading.Thread(target=self.start_process_th)
		self.process_th.daemon = True
		self.process_th.start()

		self.listen_th.join()
		self.process_th.join()


	def start_listen_th(self) -> None:
		logging.debug(f"Session listener thread started on port {self.listen_port}....")
		while not self.listen_th_end.is_set() and not self.process_th_end.is_set():
			sniff(filter=f'tcp and dst port {self.listen_port}', prn=self.handle_msg_packet)

	def handle_msg_packet(self, packet) -> None:
		logging.info(f"Packet received. 	FROM: {packet[IP].src}		DATA: {packet[TCP].ack - 1}")
		self.comms_queue.put(int(packet[TCP].ack - 1))
		self.send_RST(address=packet[IP].src, port=packet[TCP].sport)


	def decode_block(self, encoded_block: int) -> str:
		message_block = []
		for i in range(consts.BLOCK_SZ):
			temp = encoded_block & consts.CHAR_MASKS[i+1]
			shiftby = ((consts.BLOCK_SZ-1)-i)*8
			message_block.append(temp >> shiftby)

		message_string = []
		[message_string.append(chr(x)) for x in message_block]
		logging.debug(f'Block decoded: {"".join(message_string)}')
		return "".join(message_string) 	

	def start_process_th(self) -> None:
		logging.debug(f"Session processor thread started....")
		self.message = ''

		while not self.process_th_end.is_set() and not self.process_th_end.is_set():
			try:
				segment = self.comms_queue.get()
			except queue.Empty:
				logging.info("Session communications queue is empty...")
				continue

			header = self.get_header(segment)

			if header == consts.CONTROL_HEADERS['END']:
				logging.info("Received END header. Message: %s", self.message)
				self.root_th_queue.put(self.message)
				self.kill()
				break
			self.message += self.decode_block(segment)

	def send_RST(self, address: str, port: int) -> None:
		send(IP(dst=address)/TCP(dport=port, flags="R"), verbose=False)

	def kill(self):
		# Kill children
		self.listen_th_end.set()
		self.process_th_end.set()

	def get_header(self, message_block: int) -> int:
		return (message_block & consts.CHAR_MASKS[0]) >> 28


def print_msg(msg):
	print(msg)

if __name__ == '__main__':
	logging.getLogger().setLevel(logging.DEBUG)
	serv = Server(listen_port=1337)
	serv.run(handler=print_msg)