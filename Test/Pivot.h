#pragma once

typedef struct _PIVOT_HELLO {
	PBUFFER pPublicKey;
	UINT64 uPeerID;
	LPSTR lpPublicKeySignature;
	PBUFFER pSessionKey;
} PIVOT_HELLO, *PPIVOT_HELLO;

typedef struct _PIVOT_PEER {
	UINT64 uPeerID;
	LPSTR lpName;
} PIVOT_PEER, *PPIVOT_PEER;

typedef struct _PIVOT_PEER_ENVELOPE {
	PPIVOT_PEER* PivotPeers;
	DWORD cPivotPeers;
	PBUFFER pData;
	PBUFFER pPivotSessionID;
	UINT64 uType;
	UINT64 PeerFailureAt;
} PIVOT_PEER_ENVELOPE, *PPIVOT_PEER_ENVELOPE;

PBUFFER MarshalPivotHello
(
	PGLOBAL_CONFIG pGlobalConfig
);

PPIVOT_PEER_ENVELOPE UnmarhsalPivotPeerEnvelope
(
	_In_ PBUFFER pInput
);

PBUFFER MarhsalPivotPeerEnvelope
(
	_In_ PPIVOT_PEER_ENVELOPE pEnvelope
);

PPIVOT_HELLO UnmarshalPivotHello
(
	PBUFFER pInput
);

VOID FreePivotPeerEnvelope
(
	_In_ PPIVOT_PEER_ENVELOPE pEnvelope
);

VOID FreePivotHello
(
	_In_ PPIVOT_HELLO pPivotHello
);

PBUFFER AgeDecryptFromPeer
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PBUFFER pSenderPublicKey,
	_In_ LPSTR lpSenderPublicKeySig,
	_In_ PBUFFER pCiphertext
);