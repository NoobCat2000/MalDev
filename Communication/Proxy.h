#pragma once

enum ProxyMode
{
	UseDefault = 0,
	UseAutoDiscovery,
	ProxyDisabled,
	UserProvided
};

typedef struct _WEB_PROXY
{
	PURI pUri;
	enum ProxyMode Mode;
} WEB_PROXY, *PWEB_PROXY;

LPSTR GetProxyConfig();
PWEB_PROXY ProxyInit
(
	_In_ enum ProxyMode Mode,
	_In_ LPSTR lpProxyPath
);

VOID FreeWebProxy
(
	_In_ PWEB_PROXY pProxy
);