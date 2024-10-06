#pragma once

struct _SLIVER_SESSION_CLIENT {
	GLOBAL_CONFIG GlobalConfig;
	LPVOID lpClient;
	SESSION_INIT Init;
	SESSION_START Start;
	SESSION_SEND Send;
	SESSION_RECV Receive;
	SESSION_CLOSE Close;
	SESSION_CLEANUP Cleanup;
	DWORD dwPollInterval;
	UINT64 uReconnectDuration;
};