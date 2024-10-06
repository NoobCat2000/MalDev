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