#include "pch.h"

LPSTR GetProxyConfig(VOID)
{
	CHAR szHttpProxy[0x100];
	DWORD dwResult = 0;
	LPSTR lpResult = NULL;

    SecureZeroMemory(szHttpProxy, sizeof(szHttpProxy));
	dwResult = GetEnvironmentVariableA("HTTP_PROXY", szHttpProxy, sizeof(szHttpProxy));
	if (dwResult > 0 && GetLastError() != ERROR_ENVVAR_NOT_FOUND) {
		lpResult = ALLOC(lstrlenA(szHttpProxy) + 1);
		lstrcpyA(lpResult, szHttpProxy);
		return lpResult;
	}

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

BOOL IsRecoverableAutoProxyError
(
    _In_ DWORD dwError
)
{
    BOOL fRecoverable = FALSE;
    if (dwError == ERROR_SUCCESS || dwError == ERROR_INVALID_PARAMETER || dwError == ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR || dwError == ERROR_WINHTTP_AUTODETECTION_FAILED || dwError == ERROR_WINHTTP_BAD_AUTO_PROXY_SCRIPT || dwError == ERROR_WINHTTP_LOGIN_FAILURE || dwError == ERROR_WINHTTP_OPERATION_CANCELLED || dwError == ERROR_WINHTTP_TIMEOUT || dwError == ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT || dwError == ERROR_WINHTTP_UNRECOGNIZED_SCHEME) {
        fRecoverable = TRUE;
    }

    return fRecoverable;
}

PWINHTTP_PROXY_INFO GetProxyForAutoSettings
(
    _In_ HINTERNET hSession,
    _In_z_ LPWSTR lpUrl,
    _In_opt_z_ LPWSTR lpAutoConfigUrl
)
{
    DWORD dwError = ERROR_SUCCESS;
    WINHTTP_AUTOPROXY_OPTIONS AutoProxyOptions;
    PWINHTTP_PROXY_INFO pResult = NULL;
    LPWSTR lpTemp = NULL;

    SecureZeroMemory(&AutoProxyOptions, sizeof(AutoProxyOptions));
    if (lpAutoConfigUrl) {
        AutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
        AutoProxyOptions.lpszAutoConfigUrl = lpAutoConfigUrl;
    }
    else {
        AutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
        AutoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
    }

    pResult = ALLOC(sizeof(WINHTTP_PROXY_INFO));
    if (!WinHttpGetProxyForUrl(hSession, lpUrl, &AutoProxyOptions, pResult)) {
        if (GetLastError() != ERROR_WINHTTP_LOGIN_FAILURE) {
            goto CLEANUP;
        }

        AutoProxyOptions.fAutoLogonIfChallenged = TRUE;
        if (!WinHttpGetProxyForUrl(hSession, lpUrl, &AutoProxyOptions, pResult)) {
            goto CLEANUP;
        }
    }

CLEANUP:
    if (pResult->lpszProxy != NULL) {
        lpTemp = pResult->lpszProxy;
        pResult->lpszProxy = DuplicateStrW(lpTemp, 0);
        GlobalFree(lpTemp);
    }

    if (pResult->lpszProxyBypass) {
        lpTemp = pResult->lpszProxyBypass;
        pResult->lpszProxyBypass = DuplicateStrW(lpTemp, 0);
        GlobalFree(lpTemp);
    }

    return pResult;
}

PWINHTTP_PROXY_INFO ResolveProxy
(
    _In_ HINTERNET hSession,
    _In_z_ LPWSTR lpUrl
)
{
    DWORD dwError = ERROR_SUCCESS;
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ProxyConfig;
    PWINHTTP_PROXY_INFO pResult = NULL;

    SecureZeroMemory(&ProxyConfig, sizeof(ProxyConfig));
    if (!WinHttpGetIEProxyConfigForCurrentUser(&ProxyConfig)) {
        dwError = GetLastError();
        if (dwError != ERROR_FILE_NOT_FOUND) {
            goto CLEANUP;
        }

        ProxyConfig.fAutoDetect = TRUE;
    }

    if (ProxyConfig.fAutoDetect) {
        pResult = GetProxyForAutoSettings(hSession, lpUrl, NULL);
        if (pResult->lpszProxy != NULL) {
            goto CLEANUP;
        }
    }

    if (ProxyConfig.lpszAutoConfigUrl) {
        pResult = GetProxyForAutoSettings(hSession, lpUrl, ProxyConfig.lpszAutoConfigUrl);
        if (pResult->lpszProxy != NULL) {
            goto CLEANUP;
        }
    }

    pResult = ALLOC(sizeof(WINHTTP_PROXY_INFO));
    if (ProxyConfig.lpszProxy == NULL) {
        pResult->dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY;
    }
    else {
        pResult->dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        pResult->lpszProxy = DuplicateStrW(ProxyConfig.lpszProxy, 0);
        pResult->lpszProxyBypass = DuplicateStrW(ProxyConfig.lpszProxyBypass, 0);
    }

CLEANUP:
    if (ProxyConfig.lpszAutoConfigUrl != NULL) {
        GlobalFree(ProxyConfig.lpszAutoConfigUrl);
    }

    if (ProxyConfig.lpszProxy != NULL) {
        GlobalFree(ProxyConfig.lpszProxy);
    }

    if (ProxyConfig.lpszProxyBypass != NULL) {
        GlobalFree(ProxyConfig.lpszProxyBypass);
    }

    return pResult;
}