import TCPBounceServer
import logging
import datetime



logging.getLogger().setLevel(logging.NOTSET)
bounce_server = TCPBounceServer.Server(listen_port=2003)


@bounce_server.block_handler()
def write_msg(package):
	if package.rcv_checksum == package.gen_checksum:
		with open("message.txt", "a") as f:
			f.write(f"{datetime.datetime.now()}: {package.payload}\n")

	else:
		logging.error("Checksums didn't match. Not writing to file.")


if __name__ == "__main__":
	bounce_server.run()