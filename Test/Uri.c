#include "pch.h"

BOOL IsValidUri
(
	_In_ LPSTR lpUri
)
{
	return PathIsURLA(lpUri);
}

PURI UriInit
(
	_In_ LPSTR lpUri
)
{
	LPWSTR lpUriW = NULL;
	LPURL_COMPONENTS pUrlComp = NULL;
	PURI lpResult = NULL;
	LPWSTR lpTemp = NULL;

	if (!IsValidUri(lpUri)) {
		return NULL;
	}

	pUrlComp = ALLOC(sizeof(URL_COMPONENTS));
	lpUriW = ConvertCharToWchar(lpUri);

	pUrlComp->dwStructSize = sizeof(URL_COMPONENTS);
	pUrlComp->dwSchemeLength = -1;
	pUrlComp->dwHostNameLength = -1;
	pUrlComp->dwUrlPathLength = -1;
	pUrlComp->dwExtraInfoLength = -1;
	if (!WinHttpCrackUrl(lpUriW, 0, 0, pUrlComp)) {
		LOG_ERROR("WinHttpCrackUrl", GetLastError());
		FREE(lpUriW);
		FREE(pUrlComp);
		return NULL;
	}

	lpResult = ALLOC(sizeof(URI));
	lpResult->bUseHttps = pUrlComp->nScheme == INTERNET_SCHEME_HTTPS;
	lpResult->wPort = pUrlComp->nPort;
	lpTemp = ExtractSubStrW(pUrlComp->lpszHostName, pUrlComp->dwHostNameLength);
	lpResult->lpHostName = ConvertWcharToChar(lpTemp);
	FREE(lpTemp);

	lpTemp = ExtractSubStrW(pUrlComp->lpszUrlPath, pUrlComp->dwUrlPathLength);
	lpResult->lpPath = ConvertWcharToChar(lpTemp);
	FREE(lpTemp);

	lpTemp = ExtractSubStrW(pUrlComp->lpszExtraInfo, pUrlComp->dwExtraInfoLength);
	lpResult->lpQuery = ConvertWcharToChar(pUrlComp->lpszExtraInfo);
	FREE(lpTemp);

	lpResult->lpPathWithQuery = StrAppendA(lpResult->lpPath, lpResult->lpQuery);
	lpResult->lpFullUri = DuplicateStrA(lpUri, 0);
	FREE(lpUriW);
	lpResult->pUrlComponent = pUrlComp;

	return lpResult;
}

VOID FreeUri
(
	_In_ PURI pUri
)
{	
	if (pUri != NULL) {
		FREE(pUri->pUrlComponent);
		FREE(pUri->lpHostName);
		FREE(pUri->lpPath);
		FREE(pUri->lpQuery);
		FREE(pUri->lpPathWithQuery);
		FREE(pUri->lpFullUri);
		FREE(pUri);
	}
}