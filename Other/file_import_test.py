import binascii
import struct

with open('test.png', 'rb') as f:
	d = f.read()

JUMP_SIZE = 3
current_index = 0
count = 0

letters = ['A', 'R', 'I', 'M']
ack = 0

# for i in letters:
# 	ack += (ack << 8) | ord(i)
# 	print(int(ack))

# print(bin(ack))

ord_letters = []
[ord_letters.append(ord(x)) for x in letters]

buf = struct.pack('')

'''
0100 0100 << 8
0100 0100 0000 0000 
'''

b_ack = bytes(ack)
count = 0
# for i in b_ack:
# 	count += 1
# print(count)
word = struct.unpack('bb', b_ack)

print(word)