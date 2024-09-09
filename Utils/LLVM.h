#pragma once

void salsa20_encrypt
(
	unsigned char* key,
	unsigned char nonce[8],
	unsigned char* buf,
	unsigned int buflen
);

void chacha20_encrypt
(
	unsigned char key[],
	unsigned char nonce[],
	unsigned char* bytes,
	unsigned long long n_bytes
);

void rc4_encrypt
(
	unsigned char* key,
	unsigned long long key_size,
	unsigned char* buffer,
	unsigned long long buffer_size
);

void xor_encrypt
(
	unsigned char* key,
	unsigned long long key_size,
	unsigned char* buffer,
	unsigned long long buffer_size
);