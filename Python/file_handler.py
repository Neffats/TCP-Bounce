import binascii
import sys

# filename = sys.argv[1]

# with open(filename, 'rb') as f:
# 	file = bytearray(f.read())

# file_part = file[:2]

# # intified = int(file_part)

# # print(f'Before: {intified}')

# # intified += 1

# # print(f'After: {intified}')

# print(file_part.chr())


MASKS = [0x000000ff, 0x0000ff00, 0x00ff0000, 0xff000000]
MSG = "ABCD"

c = b'\x00\x00\x00\x00'
print(f'Length: {len(c)}')
e = []

for l in MSG:
	c = int(c) | ord(l)
	c = c << 8
	
	

# print(bin(c))

# for i in range(4):
# 	let = c & MASKS[i]
# 	print(bin(let))
# 	print((3-i) * 8)
# 	let = let >> ((3-i) * 8)
# 	print(bin(let))
# 	print(let)
# 	e.append(chr(let))





#0100 0001 0100 0010 0100 0011 0100 0100
