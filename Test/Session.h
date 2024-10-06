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
	UINT64 uReconnectDuration;
};