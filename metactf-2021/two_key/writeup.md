# MetaCTF 2021 - Two Key Crypto - Writeup

Let me be the first to say I hate this. It's a pwn btw.

# Source Analysis

So the encryption used appears to be a symmetric encryption scheme, with the key derived from XORing together two keys. The actual encryption itself appears to be pretty solid (at least to non nation-state attacks), and I was unable to find a way a way to break it. One important note is that this appears to be a CBC cipher, which will come in handy later.

```c
void encrypt_block(unsigned char* block, unsigned char* key){
	unsigned char local_key[0x10];
	uint64_t* numblock = (uint64_t*) block;
	memcpy(local_key, key, 0x10);

	for(int i = 0; i < 32; i++){
		uint64_t itrkey = get_key_schedule(local_key);
		uint64_t left = numblock[0];
		uint64_t right = numblock[1];

		char buf[0x21];
		to_hex(buf, block, 0x10);

		left = (left ^ right) * 0xd039a8f8aa49f551ULL + 0xd37aca18132119c5ULL;
		right ^= itrkey;

		numblock[0] = right;
		numblock[1] = left;

		to_hex(buf, block, 0x10);
	}
}
```
This is how the code generates the keys and IV for the encryption.
```c
unsigned char server_IV[0x10];  // 128 bits
unsigned char client_IV[0x10];  // 128 bits
unsigned char server_key[0x10]; // 128 bits
unsigned char client_key[0x10]; // 128 bits

memset(server_IV, 0, 0x10);
memset(client_IV, 0, 0x10);
memset(server_key, 0, 0x10);
memset(client_key, 0, 0x10);

/* Prepare combined key by copying the server key then xoring in the 
 * client key (at different offsets) */
for(i = 0; server_key[i]; i++)
	full_key[(i * 7 + 8) & 0xF] = server_key[i];
for(i = 0; client_key[i]; i++)
	full_key[(i * 9 + 8) & 0xF] ^= client_key[i];

/* Use the same logic for the IV as for the combined key */
for(i = 0; server_IV[i]; i++)
	IV[(i * 7 + 8) & 0xF] = server_IV[i];
for(i = 0; client_IV[i]; i++)
	IV[(i * 9 + 8) & 0xF] ^= client_IV[i];
```
My pwn sense is already tingling. There is no reason you make the loop dependent on stopping at a null byte instead of using indexes unless you want to make it vulnerable to overruns, and we see there is no null byte terminating any of these values as the arrays should be 0x11. We step through a debugger and find the memory locations of the following arrays. We need to do this *in the original binary*, as the stack layout is different....

```c
// 0x7fffffffcdd0 server_key
// 0x7fffffffcdf0 server_IV
// 0x7fffffffcdc0 client_key
// 0x7fffffffcde0 client_iv
```
So `server_key` is followed by `client_iv`, and `client_key` is followed by `server_key`. If we set `client_iv` and `client_key` to a 15-long string (so it doesn't read more than we want it to), we will control the vast majority of the bits used in the key. This is because the first loop will overwrite the key with our iv, which will be xored with our key, setting them to 0. In CBC mode, the IV only really affects the first block for decrypting, so we can ignore it for now.

## Exploiting

Running this locally and inspecting the key in the debugger gives us the values of the key given our input of `111111111111111` for both they key and iv. As expected, most of the bits cancel out, and there's only one byte which we have to brute force.

```
unsigned char key[16]={0, /* this changes */ 0x50,0,0,0,0,0,0,0,0,0,0,0,0,0,0x31};
```
With this, we can write a simple program (read: modify existing) in order to decrypt this. Let's get the values from the server.
```
$ nc host.cg21.metaproblems.com 3370
Please enter your key (up to 16 characters): 111111111111111
Please enter your IV (up to 16 characters): 111111111111111
47e64bc09b39e3311dab6e1604ed7c4aa3212bd3231497dc89de4a1ff421d96ad12d9d59e1d0037f72814de8435609b5f587aa9129b4cfb1f031fd4f2116b4de541bb8017115851a89d036780533d2c336885880344928bbe12bdfc813d295cf9b3a3d01e21802dd4a5c56f7e1881091801047e655cdd17accebecc8c55f0280
```

And solve:
```
int main() {
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
```

## Conclusion

After examining all 256 outputs, we get the output.
```
<bunch of gibberish> It is very nice. I wish you best of luck decrypting it. The flag is MetaCTF{we_lied_this_is_binex_not_crypto}.
```
