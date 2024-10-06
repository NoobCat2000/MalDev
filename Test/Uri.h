#pragma once

struct _URI {
	LPSTR lpFullUri;
	WORD wPort;
	BOOL bUseHttps;
	LPSTR lpHostName;
	LPSTR lpPath;
	LPSTR lpQuery;
	LPSTR lpPathWithQuery;
	LPURL_COMPONENTS pUrlComponent;
};

PURI UriInit
(
	_In_ LPSTR lpUri
);

VOID FreeUri
(
	_In_ PURI pUri
);