#pragma once

typedef BOOL(WINAPI* SOCKET_SEND)(LPVOID, PBUFFER);
typedef PBUFFER(WINAPI* SOCKET_RECV)(LPVOID);

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

typedef struct _PIVOT_CONNECTION {
	LPVOID lpClient;
	PGLOBAL_CONFIG pConfig;
	PPIVOT_LISTENER pListener;
} PIVOT_CONNECTION, *PPIVOT_CONNECTION;

typedef struct _PIVOT_LISTENER {
	ULONG_PTR ListenHandle;
	DWORD dwListenerId;
	LPSTR lpBindAddress;
	DWORD dwType;
	PPIVOT_CONNECTION* Connections;
	DWORD dwNumberOfConnections;
	HANDLE hEvent;

	// Cac phuong thuc
	SOCKET_SEND RawSend;
	SOCKET_RECV RawRecv;
	SEND_EVELOPE SendEnvelope;
	RECV_EVELOPE RecvEnvelope;

	// thong tin chung
	LPVOID lpClient;
	PGLOBAL_CONFIG pConfig;
} PIVOT_LISTENER, *PPIVOT_LISTENER;

typedef enum _PivotType {
	PivotType_TCP,
	PivotType_UDP,
	PivotType_NamedPipe
} PivotType;

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

VOID FreePivotListener
(
	_In_ PPIVOT_LISTENER pPivoListener
);