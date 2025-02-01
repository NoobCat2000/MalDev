#pragma once

typedef struct _PIVOT_CONNECTION PIVOT_CONNECTION, * PPIVOT_CONNECTION;
typedef struct _PIVOT_LISTENER PIVOT_LISTENER, * PPIVOT_LISTENER;

typedef BOOL(WINAPI* SOCKET_SEND)(LPVOID, PBUFFER);
typedef PBUFFER(WINAPI* SOCKET_RECV)(LPVOID);
typedef PPIVOT_CONNECTION(WINAPI* SOCKET_ACCEPT)(LPVOID);
typedef VOID(WINAPI* SOCKET_CLOSE)(LPVOID);
typedef VOID(WINAPI* SOCKET_CLEANUP)(LPVOID);

typedef struct _PIVOT_HELLO {
	PBUFFER pPublicKey;
	UINT64 uPeerID;
	HANDLE hThread;
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

struct _PIVOT_CONNECTION {
	UINT64 uDownstreamPeerID;
	BYTE SessionKey[CHACHA20_KEY_SIZE];
	PPIVOT_LISTENER pListener;
	LPSTR lpRemoteAddress;
	LPVOID lpDownstreamConn;
};

struct _PIVOT_LISTENER {
	ULONG_PTR ListenHandle;
	DWORD dwListenerId;
	LPSTR lpBindAddress;
	DWORD dwType;
	PPIVOT_CONNECTION* Connections;
	DWORD dwNumberOfConnections;
	CRITICAL_SECTION Lock;
	HANDLE hThread;
	BOOL IsExiting;

	// Downstream
	SOCKET_ACCEPT Accept;
	SOCKET_CLOSE Close;
	SOCKET_CLEANUP Cleanup;
	SOCKET_SEND RawSend;
	SOCKET_RECV RawRecv;

	// thong tin chung
	LPVOID lpUpstream;
	PGLOBAL_CONFIG pConfig;
};

typedef enum _PeerFailureType {
	PeerFailureType_SEND_FAILURE,
	PeerFailureType_DISCONNECT
} PeerFailureType;

typedef enum _PivotType {
	PivotType_TCP,
	PivotType_UDP,
	PivotType_NamedPipe
} PivotType;

PBUFFER MarshalPivotHello
(
	_In_ PGLOBAL_CONFIG pGlobalConfig,
	_In_ PBUFFER pSessionKey
);

PPIVOT_PEER_ENVELOPE UnmarshalPivotPeerEnvelope
(
	_In_ PBUFFER pInput
);

PBUFFER MarshalPivotPeerEnvelope
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

PBUFFER AgeEncryptToPeer
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PBUFFER pRecipientPublicKey,
	_In_ LPSTR lpRecipientPublicKeySig,
	_In_ PBUFFER pPlaintext
);

VOID FreePivotListener
(
	_In_ PPIVOT_LISTENER pPivoListener
);

BOOL PeerKeyExchange
(
	_In_ PPIVOT_CONNECTION pConnection
);

VOID PivotConnectionStart
(
	_In_ PPIVOT_CONNECTION pConnection
);

VOID ListenerMainLoop
(
	_In_ PPIVOT_LISTENER pListener
);

BOOL WriteEnvelopeToPeer
(
	_In_ PPIVOT_CONNECTION pConnection,
	_In_ PENVELOPE pEnvelope
);

PENVELOPE ReadEnvelopeFromPeer
(
	_In_ PPIVOT_CONNECTION pConnection
);

PBUFFER MarshalPivotPeerFailure
(
	_In_ UINT64 uPeerID,
	_In_ PeerFailureType FailureType,
	_In_ LPSTR lpError
);