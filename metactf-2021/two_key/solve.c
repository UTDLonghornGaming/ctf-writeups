#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

const char* SEARCH = "0123456789abcdef";

void from_hex(char* out, char* buf, int len){
	for(int i = 0; i < len; i += 2){
		char first = (strchr(SEARCH, buf[i]) - SEARCH) << 4;
		char second = (strchr(SEARCH, buf[i + 1]) - SEARCH);
		out[i / 2] = first | second;
	}
	out[len / 2 + 1] = 0;
}

uint64_t get_key_schedule(char* key){
	char start = 0;
	uint64_t value = 0;

	for(int i = 0; i < 0x10; i++)
		start ^= ((i + 1) * key[i]) & 0x7F;

	/* Pick 64 bits from the 128 bit key */
	for(int i = 0; i < 64; i++){
		value = (value << 1) | ((key[start / 8] >> (start % 8)) & 1);
		start = (start * 57 + 13) % 128;	
	}

	/* Modify the key based on the selected value */
	for(int i = 0; i < 0x10; i++)
		key[i] ^= ((char*)(&value))[i % 8];

	return value;
}


void decrypt_block(char* block, char* key){
	char local_key[0x10];
	uint64_t itrkeys[0x20];
	uint64_t* numblock = (uint64_t*) block;

	memcpy(local_key, key, 0x10);

	for(int i = 0; i < 32; i++)
		itrkeys[i] = get_key_schedule(local_key);

	/* Undo what we did to encrypt the block */
	for(int i = 31; i >= 0; i--){
		uint64_t right = numblock[0];
		uint64_t left = numblock[1];

		right ^= itrkeys[i];
		/* Subtract the amount we added, then multiply by the mod inverse */
		left = ((left - 0xd37aca18132119c5ULL) * 0x376ce7a50c8a73b1ULL) ^ right;

		numblock[0] = left;
		numblock[1] = right;
	}
}

bool decrypt(char* message, int len, char* key, char* iv){
	bool success = false;
	int i = 0;
	int j = 0;
	char cur_iv[16];
	char next_iv[16];

	if(len % 16 != 0)
		goto end;
	
	for(i = 0; i < len; i += 16){
		memcpy(cur_iv, iv, 16);
		memcpy(next_iv, message + i, 16);
		decrypt_block(message + i, key);

		for(j = 0; j < 16; j++)
			message[i + j] ^= cur_iv[j];

		iv = next_iv;
	}

	success = true;

end:
	return success;
}

int main(int argc, char** argv){
	for(int i = 0; i < 256; i++) {
		unsigned char iv[16] = {};
		unsigned char key[16]={0,i,0,0,0,0,0,0,0,0,0,0,0,0,0,0x31};

		char* in = "47e64bc09b39e3311dab6e1604ed7c4aa3212bd3231497dc89de4a1ff421d96ad12d9d59e1d0037f72814de8435609b5f587aa9129b4cfb1f031fd4f2116b4de541bb8017115851a89d036780533d2c336885880344928bbe12bdfc813d295cf9b3a3d01e21802dd4a5c56f7e1881091801047e655cdd17accebecc8c55f0280";

		char flag[2048];
		memset(flag, 0, 2048);
		from_hex(flag, in, strlen(in));
		decrypt(flag, strlen(flag), key, iv);

		for (int i = 0; i < strlen(flag); i++) {
			if(flag[i] == '\n' || flag[i] == '\t') {
				flag[i] = ' ';
			}
		}
		printf("%s\n", flag);
	}
	return 0;
}
