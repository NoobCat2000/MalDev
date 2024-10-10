#pragma once

typedef struct _BEACON_TASK {
	LPSTR lpInstanceID;
	PENVELOPE* EnvelopeList;
	DWORD dwNumberOfEnvelopes;
	DWORD dwNextCheckin;
} BEACON_TASK, *PBEACON_TASK;

typedef struct _BEACON_TASKS_WRAPPER {
	PSLIVER_BEACON_CLIENT pBeacon;
	HANDLE hEvent;
	PENVELOPE* pTaskList;
	DWORD dwNumberOfTasks;
} BEACON_TASKS_WRAPPER, *PBEACON_TASKS_WRAPPER;

struct _SLIVER_BEACON_CLIENT {
	PGLOBAL_CONFIG pGlobalConfig;
	LPVOID lpClient;
	CLIENT_INIT Init;
	CLIENT_START Start;
	CLIENT_SEND Send;
	CLIENT_RECV Receive;
	CLIENT_CLOSE Close;
	CLIENT_CLEANUP Cleanup;
	CHAR szInstanceID[37];
	DWORD dwInterval;
	DWORD dwJitter;
};

PSLIVER_BEACON_CLIENT BeaconInit
(
	_In_ PGLOBAL_CONFIG pGlobalConfig
);

VOID BeaconMainLoop
(
	_In_ PSLIVER_BEACON_CLIENT pBeaconClient
);

VOID FreeBeaconClient
(
	_In_ PSLIVER_BEACON_CLIENT pBeaconClient
);

