#pragma once

typedef enum _ProxyMode
{
	UseDefault = 0,
	UseAutoDiscovery,
	ProxyDisabled,
	UserProvided
} ProxyMode;

typedef struct _WEB_PROXY
{
	PURI pUri;
	ProxyMode Mode;
} WEB_PROXY, *PWEB_PROXY;

LPSTR GetProxyConfig();
PWEB_PROXY ProxyInit
(
	_In_ ProxyMode Mode,
	_In_ LPSTR lpProxyPath
);

VOID FreeWebProxy
(
	_In_ PWEB_PROXY pProxy
);