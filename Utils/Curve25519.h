#pragma once

#define F25519_SIZE 32
#define X25519_KEY_SIZE (32)
#define X25519_SHARED_SIZE (32)
#define X25519_SCALAR_SIZE (32)

typedef struct _STANZA {
	LPSTR lpType;
	LPSTR* pArgs;
	DWORD dwArgc;
	PBYTE pBody;
	DWORD cbBody;
} STANZA, *PSTANZA;

VOID ComputeX25519
(
	_Out_ PBYTE pSharedSecret,
	_In_ PBYTE pMyPrivateKey,
	_In_ PBYTE pTheirPublicKey
);

PSTANZA AgeRecipientWrap
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer,
	_In_ PBYTE pTheirPubKey
);