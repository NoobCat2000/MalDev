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
	URL_COMPONENTS* pUrlComp = NULL;
	PURI lpResult = NULL;
	LPWSTR lpTemp = NULL;

	if (!IsValidUri(lpUri)) {
		LogErrorA("IsValidUri failed at %s (lpUri=%s)\n", __FUNCTION__, lpUri);
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
		LogError(L"WinHttpCrackUrl failed at: %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
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

	lpResult->lpPathWithQuery = ALLOC(lstrlenA(lpResult->lpPath) + lstrlenA(lpResult->lpQuery) + 1);
	wsprintfA(lpResult->lpPathWithQuery, "%s%s", lpResult->lpPath, lpResult->lpQuery);
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
		if (pUri->pUrlComponent != NULL) {
			FREE(pUri->pUrlComponent);
		}

		if (pUri->lpHostName != NULL) {
			FREE(pUri->lpHostName);
		}

		if (pUri->lpPath != NULL) {
			FREE(pUri->lpPath);
		}

		if (pUri->lpQuery != NULL) {
			FREE(pUri->lpQuery);
		}

		if (pUri->lpPathWithQuery != NULL) {
			FREE(pUri->lpPathWithQuery);
		}

		if (pUri->lpFullUri != NULL) {
			FREE(pUri->lpFullUri);
		}

		FREE(pUri);
	}
}