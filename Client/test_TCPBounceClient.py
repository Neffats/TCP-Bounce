import unittest
import TCPBounceClient
import consts
from scapy.all import *
import time
import threading
import consts as tcpconsts


class TestBlockSender(unittest.TestCase):
	def setUp(self):
		bouncepoints_raw = ["127.0.0.1"]

		self.client = TCPBounceClient.Block_Sender(
			# TODO: Get localhost IP address.
			receiver_address="192.168.1.70", 
			receiver_message_port=5001, 
			receiver_init_port=5000, 
			bounce_endpoints=bouncepoints_raw, 
			bounce_port=443)

	def test_encode_block(self):
		testcases = [
			{"Case": "AAA", "Want": 4276545},
			{"Case": "ABC", "Want": 4276803},
			{"Case": "1l!", "Want": 3238945},]

		for c in testcases:
			self.assertEqual(self.client.encode_block(c["Case"]), c["Want"])

		with self.assertRaises(ValueError):
			self.client.encode_block("A"*(tcpconsts.BLOCK_SZ-1))
		with self.assertRaises(ValueError):
			self.client.encode_block("A"*(tcpconsts.BLOCK_SZ+1))   

	def test_decode_block(self):
		testcases = [
			{"Case": 4276545, "Want": "AAA"},]

		for c in testcases:
			self.assertEqual(self.client.decode_block(c["Case"]), c['Want'])

	def test_add_header(self):
		testcases = [
			{"Case": [4276545, 'DATA'], "Want": 272712001},
			{"Case": [4276803, 'DATA'], "Want": 272712259},
			{"Case": [3238945, 'DATA'], "Want": 271674401},]

		for c in testcases:
			self.assertEqual(self.client.add_header(c['Case'][0], c['Case'][1]), c['Want'])

	def test_send(self):
		self.test_message = "This is a test message."

		self.test_server_th = threading.Thread(target=self.run_fake_server)
		self.test_server_th.daemon = True
		self.test_server_th.start()

		time.sleep(0.2)

		self.client.send(self.test_message)


	def run_fake_server(self):
		self.finished = False
		self.packet_count = 0

		self.expected = [273967209, 275980393, 275980385, 270562405, 276001824, 275604851, 275997031, 275066368]

		# This is a test message.
		sniff(filter=f'tcp and dst port {5000}', prn=self.handle_init)
		while not self.finished: 
			sniff(filter=f'tcp and dst port {5001}', prn=self.handle_msg)

	def handle_init(self, packet):
		packet_data = int(packet[TCP].ack-1)

		self.send_RST(address=packet[IP].src, port=packet[TCP].sport)
		self.assertEqual(packet_data, 270013321)

	def handle_msg(self, packet):
		packet_data = int(packet[TCP].ack-1)
		self.send_RST(address=packet[IP].src, port=packet[TCP].sport)

		if packet_data == 4026531840:
			self.finished = True
			return

		self.assertEqual(packet_data, self.expected[packet_count])
		self.packet_count += 1

	def send_RST(self, address: str, port: int) -> None:
		send(IP(dst=address)/TCP(dport=port, flags="R"), verbose=False)


if __name__ == "__main__":
	unittest.main()
