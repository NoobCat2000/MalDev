#pragma once

#define SHA256_HASH_SIZE (32)
#define SHA256_BLOCK_SIZE (64)

PBYTE ComputeSHA256
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