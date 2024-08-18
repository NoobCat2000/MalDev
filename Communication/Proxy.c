#include "pch.h"

LPSTR GetProxyConfig()
{
	CHAR szHttpProxy[0x100];
	DWORD dwResult = 0;
	LPSTR lpResult = NULL;

	dwResult = GetEnvironmentVariableA("HTTP_PROXY", szHttpProxy, sizeof(szHttpProxy));
	if (dwResult > 0 && GetLastError() != ERROR_ENVVAR_NOT_FOUND) {
		lpResult = ALLOC(lstrlenA(szHttpProxy) + 1);
		lstrcpyA(lpResult, szHttpProxy);
		return lpResult;
	}

	SecureZeroMemory(szHttpProxy, sizeof(szHttpProxy));
	dwResult = GetEnvironmentVariableA("HTTPS_PROXY", szHttpProxy, sizeof(szHttpProxy));
	if (dwResult > 0 && GetLastError() != ERROR_ENVVAR_NOT_FOUND) {
		lpResult = ALLOC(lstrlenA(szHttpProxy) + 1);
		lstrcpyA(lpResult, szHttpProxy);
		return lpResult;
	}

	return NULL;
}

PWEB_PROXY ProxyInit
(
	_In_ ProxyMode Mode,
	_In_ LPSTR lpProxyPath
)
{
	PWEB_PROXY lpResult = NULL;

	lpResult = ALLOC(sizeof(WEB_PROXY));
	lpResult->Mode = Mode;
	if (Mode != UseAutoDiscovery && lpProxyPath != NULL) {
		lpResult->pUri = UriInit(lpProxyPath);
	}
}

VOID FreeWebProxy
(
	_In_ PWEB_PROXY pProxy
)
{
	if (pProxy != NULL) {
		FreeUri(pProxy->pUri);
		FREE(pProxy);
	}
}