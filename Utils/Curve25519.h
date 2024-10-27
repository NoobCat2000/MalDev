#pragma once

#define F25519_SIZE 32
#define X25519_KEY_SIZE (32)
#define X25519_SHARED_SIZE (32)
#define X25519_SCALAR_SIZE (32)
#define ED25519_SIGNATURE_SIZE (64)
#define HASH_EDDSA (0x4445)

typedef struct _STANZA {
	LPSTR lpType;
	LPSTR* pArgs;
	DWORD dwArgc;
	PBYTE pBody;
	DWORD cbBody;
} STANZA, *PSTANZA;

typedef struct _STANZA_WRAPPER {
	PBUFFER pMac;
	PSTANZA* Recipients;
	DWORD cRecipients;
	PBUFFER pPayload;
} STANZA_WRAPPER, *PSTANZA_WRAPPER;

typedef struct _ED25519_GE_P2 {
	UINT32 X[10];
	UINT32 Y[10];
	UINT32 Z[10];
} ED25519_GE_P2, * PED25519_GE_P2;

typedef struct _ED25519_GE_P3 {
	UINT32 X[10];
	UINT32 Y[10];
	UINT32 Z[10];
	UINT32 T[10];
} ED25519_GE_P3, *PED25519_GE_P3;

typedef struct _ED25519_GE_P1P1 {
	UINT32 X[10];
	UINT32 Y[10];
	UINT32 Z[10];
	UINT32 T[10];
} ED25519_GE_P1P1, * PED25519_GE_P1P1;

typedef struct _ED25519_GE_PRECOMP {
	UINT32 yplusx[10];
	UINT32 yminusx[10];
	UINT32 xy2d[10];
} ED25519_GE_PRECOMP, * PED25519_GE_PRECOMP;

typedef struct _ED25519_GE_CACHED {
	UINT32 YplusX[10];
	UINT32 YminusX[10];
	UINT32 Z[10];
	UINT32 T2d[10];
} ED25519_GE_CACHED, *PED25519_GE_CACHED;

typedef struct _X25519_IDENTITY {
	PBYTE pSecretKey;
	PBYTE pOurPublicKey;
} X25519_IDENTITY, *PX25519_IDENTITY;

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

VOID FreeStanza
(
	_In_ PSTANZA pInput
);

BOOL ED25519Verify
(
	_In_ PBYTE pSignature,
	_In_ PBYTE pMessage,
	_In_ DWORD cbMessage,
	_In_ PBYTE pPublicKey
);

VOID FreeStanza
(
	_In_ PSTANZA pInput
);