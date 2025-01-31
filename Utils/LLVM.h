#pragma once

#define HASHA(API)		    (_HashStringRotr32A((PCHAR) API))

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
	DWORD dwModuleHash,
	DWORD dwApiHash
);

//HMODULE GetModuleHandleH
//(
//	_In_ DWORD ModuleHash
//);

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
	_In_ UINT8 DontKnow
);

INT32 MemCmp
(
	_In_ PBYTE pBuffer1,
	_In_ PBYTE pBuffer2,
	_In_ UINT64 uSize
);

DWORD _HashStringRotr32A
(
	PCHAR String
);