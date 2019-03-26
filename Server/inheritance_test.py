import threading


class base(threading.Thread):
	def __init__(self, name):
		threading.Thread.__init__(self)
		self.name = name


class oneUP(base):
	def __init__(self, name, colour):
		base.__init__(self, name)
		self.colour = colour

	def run(self):
		print(f"oneUP Thread: {self.name}")


if __name__ == '__main__':
	n = oneUP("Steffan", "Red")

	n.start()