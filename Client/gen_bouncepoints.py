import url_retreiver
import logging
import sys

def main():
	src = sys.argv[1]

	logging.getLogger().setLevel(logging.INFO)
	ret = url_retreiver.URL_Retreiver(src, "bouncepoints.txt")

	ret.get_info()

if __name__ == "__main__":
	main()