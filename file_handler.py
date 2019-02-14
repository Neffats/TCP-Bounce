import binascii
import sys

CHUNK_SZ = 4
MASKS = [0xFF000000, 0x00FF0000, 0x0000FF00, 0x000000FF]
MSG = "The Time Machine is a science fiction novella by H. G. Wells, published in 1895 and written as a frame narrative"

c = 0
e = []

		
	
def encode_chunk(letters):
	encoded = 0
	for i in range(len(letters)-1):
		encoded = int(encoded) | ord(letters[i])
		encoded = encoded << 8

	encoded = int(encoded) | ord(letters[-1])

	return encoded

a = encode_chunk(MSG)
print(encode_chunk(MSG))


def decode_chunk(encoded):
	message_chunk = []
	for i in range(CHUNK_SZ):
		temp = encoded & MASKS[i]
		shiftby = ((CHUNK_SZ-1)-i)*8
		message_chunk.append(temp >> shiftby)

	message_string = []

	[message_string.append(chr(x)) for x in message_chunk]
	return "".join(message_string) 

print(decode_chunk(a))


encoded_time_machine = []

index = 0

while index < len(MSG):
	encoded_time_machine.append(encode_chunk(MSG[index:index+CHUNK_SZ]))
	index += CHUNK_SZ

print(encoded_time_machine)

decoded_time_machine = []

for i in encoded_time_machine:
	decoded_time_machine.append(decode_chunk(i))
	
print("".join(decoded_time_machine))
# char decode_chunk(uint32_t encoded_chunk){
# 	uint32_t temp = 0;
#     char final[CHUNK];
    
#     for(int i = 0; i <= CHUNK-1; i++){
#     	temp = encoded_chunk & MASKS[i];
#     	printf("After AND with %u --> %u\n", MASKS[i], temp);
#     	uint32_t shiftBy = ((CHUNK-1)-i) * 8;
#     	printf("Shifted by --> %u\n", shiftBy);
#     	final[i] = temp >> shiftBy;
#     	printf("Final --> %u\n\n", final[i]); 
#     }

#     return final;
