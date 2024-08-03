#pragma once

typedef struct _URI {
	LPSTR lpFullUri;
	WORD wPort;
	BOOL bUseHttps;
	LPSTR lpHostName;
	LPSTR lpPath;
	LPSTR lpQuery;
	LPSTR lpPathWithQuery;
	URL_COMPONENTS* pUrlComponent;
} URI, *PURI;

PURI UriInit
(
	_In_ LPSTR lpUri
);

VOID FreeUri
(
	_In_ PURI pUri
);