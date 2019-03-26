#include <stdio.h>
#include <stdint.h>

#define CHUNK 4

uint32_t MASKS[4] = { 0xFF000000, 0x00FF0000, 0x0000FF00, 0x000000FF};

uint32_t encode_chunk(char *msg_chunk);


int main(int argc, char *argv[]){

	if(argc < 2 | argc > 2){
		printf("Usage: test.exe <message>");
		return -1;
	}

	printf("%s\n", argv[1]);

	char msg[] = {'A', 'B', 'C', 'D'};
	printf("SIZE of msg: %d\n\n", sizeof(msg));
	uint32_t in = encode_chunk(msg);
	
	printf("-------------------------------------------\n\n");
    uint32_t temp = 0;
    char final[CHUNK];
    
    for(int i = 0; i <= CHUNK-1; i++){
    	temp = in & MASKS[i];
    	printf("After AND with %u --> %u\n", MASKS[i], temp);
    	uint32_t shiftBy = ((CHUNK-1)-i) * 8;
    	printf("Shifted by --> %u\n", shiftBy);
    	final[i] = temp >> shiftBy;
    	printf("Final --> %u\n\n", final[i]); 
    }

    for(int i = 0; i < sizeof(final); i++){
    	printf("Letter --> %c\n", final[i]);
    }

    return 0;
}

uint32_t encode_chunk(char *msg_chunk){
	uint32_t encoded_chunk = 0;

	printf("Size of message chunk is: %d\n", sizeof(*msg_chunk));

	for(int i = 0; i < CHUNK-1; i++){
		printf("Letter %c ---------> %d\n",msg_chunk[i], msg_chunk[i]); 
		encoded_chunk |= msg_chunk[i];
		printf("After OR --> %d\n", encoded_chunk);
		encoded_chunk <<= 8;
		printf("After SHIFT --> %d\n\n", encoded_chunk);
	}
	encoded_chunk |= msg_chunk[CHUNK-1];
    printf("Final int --> %d\n", encoded_chunk); 

    return encoded_chunk;
}

//1,094,861,636