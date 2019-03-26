import TCPBounceClient
import sys


msg = sys.argv[1]
bouncepoints_src = sys.argv[2]

with open(bouncepoints_src, "r") as f:
	bouncepoints_raw = f.readlines()

bouncepoints = []

for x in bouncepoints_raw:
	bouncepoints.append(x.strip("\n"))


sender = TCPBounceClient.Block_Sender(receiver_address="192.168.1.107", receiver_message_port=3000, receiver_init_port=1337, bounce_endpoints=bouncepoints, bounce_port=443)

sender.send(msg)

