#pragma once

#define SHA256_HASH_SIZE (32)
#define SHA512_HASH_SIZE (64)
#define SHA256_BLOCK_SIZE (64)
#define BLAKE2B_BLOCKBYTES (128)
#define BLAKE2B_SALTBYTES (16)
#define BLAKE2B_PERSONALBYTES (16)
#define BLAKE2B_OUTBYTES (64)

typedef struct _BLAKE2B_PARAM {
	UINT8 cbDigest;
	UINT8 cbKey;
	UINT8 uFanOut;
	UINT8 uDepth;
	UINT32 cbLeaf;
	UINT64 uNodeOffset;
	UINT8 uNodeDepth;
	UINT8 cbInner;
	UINT8 Reserved[14];
	UINT8 Salt[BLAKE2B_SALTBYTES];
	UINT8 Personal[BLAKE2B_PERSONALBYTES];
} BLAKE2B_PARAM, * PBLAKE2B_PARAM;

typedef struct _BLAKE2B_STATE {
	UINT64 h[8];
	UINT64 t[2];
	UINT64 f[2];
	UINT8 Buffer[BLAKE2B_BLOCKBYTES];
	DWORD cbBuffer;
	DWORD cbOutput;
} BLAKE2B_STATE, *PBLAKE2B_STATE;

PBYTE ComputeSHA256
(
	_In_ PBYTE pbData,
	_In_ DWORD dwDataLen
);

PBYTE ComputeSHA512
(
	_In_ PBYTE pbData,
	_In_ DWORD dwDataLen
);

PBYTE HKDFGenerate
(
	_In_ PBYTE pSalt,
	_In_ DWORD cbSalt,
	_In_ PBYTE pIKM,
	_In_ DWORD cbIKM,
	_In_ PBYTE pInfo,
	_In_ DWORD cbInfo,
	_In_ DWORD cbDerivedKey
);

PBYTE Blake2B
(
	_In_ PBYTE pData,
	_In_ DWORD cbData,
	_In_ PBYTE pKey,
	_In_ DWORD cbKey
);