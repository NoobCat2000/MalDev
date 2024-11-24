#pragma once

typedef enum _ProxyMode
{
	UseDefault = 0,
	UseAutoDiscovery,
	ProxyDisabled,
	UserProvided
} ProxyMode;

struct _WEB_PROXY
{
	PURI pUri;
	ProxyMode Mode;
};

LPSTR GetProxyConfig(VOID);
PWEB_PROXY ProxyInit
(
	_In_ ProxyMode Mode,
	_In_ LPSTR lpProxyPath
);

VOID FreeWebProxy
(
	_In_ PWEB_PROXY pProxy
);

PWINHTTP_PROXY_INFO ResolveProxy
(
	_In_ HINTERNET hSession,
	_In_z_ LPWSTR lpUrl
);

VOID FreeWinHttpProxyInfo
(
	_In_ PWINHTTP_PROXY_INFO pProxyInfo
);