#pragma once

typedef struct _BEACON_TASK {
	LPSTR lpInstanceID;
	PENVELOPE pEnvelopes;
	DWORD dwNumberOfEnvelopes;
	DWORD dwNextCheckin;
} BEACON_TASK, *PBEACON_TASK;