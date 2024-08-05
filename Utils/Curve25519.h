#pragma once

#define F25519_SIZE 32
#define X25519_KEY_SIZE (32)
#define X25519_SHARED_SIZE (32)

typedef struct _STANZA {
	LPSTR lpType;
	LPSTR* pArgs;
	PBYTE pBody;
} STANZA, *PSTANZA;

VOID ComputeX25519
(
	_Out_ PBYTE pSharedSecret,
	_In_ PBYTE pMyPrivateKey,
	_In_ PBYTE pTheirPublicKey
);