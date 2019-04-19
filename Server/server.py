import TCPBounceServer
import logging
import datetime

def write_msg(msg):
	with open("message.txt", "a") as f:
		f.write(f"{datetime.datetime.now()}: {msg}\n")

logging.getLogger().setLevel(logging.DEBUG)
bounce_server = TCPBounceServer.Server(listen_port=2003)

bounce_server.run(handler=write_msg)