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

FARPROC GetProcAddressH
(
	DWORD moduleHash,
	DWORD Hash
);

VOID MemSet
(
	_In_ PBYTE pBuffer,
	_In_ BYTE Value,
	_In_ UINT64 uSize,
	_In_ BOOL DontKnow
);

VOID MemCopy
(
	_In_ PBYTE pDest,
	_In_ PBYTE pSrc,
	_In_ UINT64 uSize,
	_In_ BOOL DontKnow
);

VOID PrintFormatA
(
	_In_ LPSTR lpFormat,
	...
);

VOID PrintFormatW
(
	_In_ LPWSTR lpFormat,
	...
);