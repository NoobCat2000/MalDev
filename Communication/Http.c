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
			FREE(lpHostName);
		}
	}

	Result->hSession = WinHttpOpen(NULL, dwAccessType, lpProxyName, lpProxyBypass, 0);
	if (!Result->hSession) {
		wprintf(L"WinHttpOpen failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		if (Result->lpProxyAutoConfigUrl != NULL) {
			FREE(Result->lpProxyAutoConfigUrl);
		}

		FREE(Result);
		goto END;
	}

END:
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
	Result->pProxyConfig = pProxyConfig;
	Result->pUri = pUri;
	Result->pHttpSession = HttpSessionInit(pProxyConfig);
	Result->hConnection = WinHttpConnect(Result->pHttpSession->hSession, lpHostName, pUri->wPort, 0);
	if (Result->hConnection == NULL) {
		wprintf(L"WinHttpConnect failed at %lls. Last error: 0x%08x\n", __FUNCTIONW__, GetLastError());
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
	swprintf(lpFullHeader, dwBufferLength, L"%lls: %lls", lpHeaderNameW, lpHeaderDataW);
	if (StrCmpW(&lpFullHeader[lstrlenW(lpFullHeader) - 2], L"\r\n")) {
		StrCatW(lpFullHeader, L"\r\n");
	}

	BOOL Result = WinHttpAddRequestHeaders(hRequest, lpFullHeader, lstrlenW(lpFullHeader), WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
	if (!Result) {
		wprintf(L"WinHttpAddRequestHeaders failed at %lls. Error code: 0x%08x.\n", __FUNCTIONW__, GetLastError());
		printf("lpHeaderName: %s; lpHeaderData: %s\n", lpHeaderName, lpHeaderData);
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
	_In_opt_ LPSTR lpContentType,
	_In_opt_ LPSTR lpData,
	_In_opt_ DWORD cbData
)
{
	LPWSTR lpMethod = NULL;
	PURI pUri = This->pUri;
	LPWSTR pPath = NULL;
	HINTERNET hRequest = NULL;
	DWORD i = 0;
	PWINHTTP_PROXY_INFO pProxyInfo = NULL;
	LPSTR xContentType = NULL;
	LPSTR xData = lpData;
	DWORD xDataSize = cbData;
	DWORD dwLastError = 0;
	DWORD dwFlag = WINHTTP_FLAG_REFRESH;

	
	pPath = ConvertCharToWchar(pUri->lpPathWithQuery);
	lpMethod = ConvertCharToWchar(GetMethodString(pRequest->Method));
	if (pUri->bUseHttps) {
		dwFlag |= WINHTTP_FLAG_SECURE;
	}

	hRequest = WinHttpOpenRequest(This->hConnection, lpMethod, pPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlag);
	if (hRequest == NULL)
	{
		goto END;
	}

	if (!WinHttpSetTimeouts(hRequest, pRequest->dwResolveTimeout, pRequest->dwConnectTimeout, pRequest->dwSendTimeout, pRequest->dwReceiveTimeout)) {
		goto END;
	}

	for (i = 0; i < _countof(pRequest->Headers); i++) {
		if (pRequest->Headers[i]) {
			SetHeader(hRequest, GetHeaderString(i), pRequest->Headers[i]);
		}
	}

	pProxyInfo = GetProxyForUrl(This->pHttpSession, This->pUri);
	if (pProxyInfo != NULL) {
		WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, pProxyInfo, sizeof(WINHTTP_PROXY_INFO));
	}

	
	if (lpContentType != NULL) {
		xContentType = DuplicateStrA(lpContentType, 0);
	}
	else if (pRequest->ContentTy != NULL) {
		xContentType = DuplicateStrA(pRequest->ContentTy, 0);
	}

	if (lpData == NULL) {
		xData = pRequest->lpData;
		xDataSize = pRequest->cbData;
	}

	if (xContentType != NULL) {
		SetHeader(hRequest, GetHeaderString(ContentType), xContentType);
	}

	while (!WinHttpSendRequest(hRequest, NULL, 0, xData, xDataSize, xDataSize, NULL)) {
		dwLastError = GetLastError();
		wprintf(L"WinHttpSendRequest failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
		if (dwLastError == ERROR_WINHTTP_RESEND_REQUEST)
		{
			continue;
		}

		if (dwLastError == ERROR_WINHTTP_SECURE_FAILURE) {
			dwFlag = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
			if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlag, sizeof(dwFlag))) {
				wprintf(L"WinHttpSetOption failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
				hRequest = NULL;
				goto END;
			}
		}
	}

	if (!WinHttpReceiveResponse(hRequest, NULL)) {
		wprintf(L"WinHttpReceiveResponse failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto END;
	}

END:
	if (lpContentType != NULL) {
		FREE(xContentType);
	}

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
		AutoProxyOpt.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
		AutoProxyOpt.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
	}
	else {
		AutoProxyOpt.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
		AutoProxyOpt.lpszAutoConfigUrl = ConvertCharToWchar(pHttpSession->lpProxyAutoConfigUrl);
	}

	AutoProxyOpt.fAutoLogonIfChallenged = TRUE;
	Result = ALLOC(sizeof(WINHTTP_PROXY_INFO));
	lpFullUri = ConvertCharToWchar(pUri->lpFullUri);
	if (!WinHttpGetProxyForUrl(pHttpSession->hSession, lpFullUri, &AutoProxyOpt, Result)) {
		goto END;
	}

END:
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
		wprintf(L"WinHttpQueryHeaders failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
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
			FREE(pHttpSession);
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
		FreeWebProxy(pHttpClient->pProxyConfig);
		if (pHttpClient->hConnection != NULL) {
			WinHttpCloseHandle(pHttpClient->hConnection);
		}
	}
}

VOID FreeHttpRequest
(
	_In_ PHTTP_REQUEST pHttpReq
)
{
	DWORD i = 0;

	if (pHttpReq != NULL) {
		if (pHttpReq->lpData != NULL) {
			FREE(pHttpReq->lpData);
		}

		if (pHttpReq->ContentTy != NULL) {
			FREE(pHttpReq->ContentTy);
		}

		for (i = 0; i < _countof(pHttpReq->Headers); i++) {
			if (pHttpReq->Headers[i] != NULL) {
				FREE(pHttpReq->Headers[i]);
			}
		}
	}
}