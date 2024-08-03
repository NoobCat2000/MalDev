#pragma once

typedef struct _GOOGLE_DRIVE {
	PWEB_PROXY pProxyConfig;
	LPSTR lpClientId;
	LPSTR lpClientSecret;
	LPSTR lpRefreshToken;
	LPSTR lpAccessToken;
	LPSTR lpUserAgent;
} GOOGLE_DRIVE, *PGOOGLE_DRIVE;

PGOOGLE_DRIVE GoogleDriveInit
(
	_In_ LPSTR lpUserAgent,
	_In_ LPSTR lpClientId,
	_In_ LPSTR lpSecret,
	_In_ LPSTR lpRefreshToken
);

BOOL RefreshAccessToken
(
	PGOOGLE_DRIVE This
);

BOOL GoogleDriveUpload
(
	_In_ PGOOGLE_DRIVE This,
	_In_ LPWSTR lpFilePath
);

BOOL GetFileId
(
	_In_ PGOOGLE_DRIVE This,
	_In_ LPSTR lpName,
	_Out_ LPSTR* pId
);

BOOL GoogleDriveDownload
(
	_In_ PGOOGLE_DRIVE This,
	_In_ LPSTR lpFileId
);