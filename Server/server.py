import TCPBounceServer
import logging
import datetime



logging.getLogger().setLevel(logging.NOTSET)
bounce_server = TCPBounceServer.Server(listen_port=2003)


@bounce_server.block_handler()
def write_msg(msg):
	with open("message.txt", "a") as f:
		f.write(f"{datetime.datetime.now()}: {msg}\n")


if __name__ == "__main__":
	bounce_server.run(handler=write_msg)