import unittest
import TCPBounceClient
import consts

class TestBlockSender(unittest.TestCase):
	def setUp(self):
		with open("bounce_endpoints.txt", "r") as f:
			bouncepoints_raw = f.readlines()

		self.client = TCPBounceClient.Block_Sender(
			# TODO: Get localhost IP address.
			receiver_address="192.168.1.70", 
			receiver_message_port=5000, 
			receiver_init_port=5001, 
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
			self.client.encode_block("A"*(consts.BLOCK_SZ-1))
		with self.assertRaises(ValueError):
			self.client.encode_block("A"*(consts.BLOCK_SZ+1))   

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

if __name__ == "__main__":
	unittest.main()
