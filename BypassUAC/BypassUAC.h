#pragma once

typedef enum _BypassType {
	Cmstp = 0,
	compMgmtLauncher
} BypassType;

typedef struct _WINDOWS_INFO {
	BOOL bIsOk;
	DWORD dwPID;
	WCHAR wszWindowsName[0x400];
} WINDOWS_INFO, * PWINDOWS_INFO;

VOID BypassUAC
(
	_In_ BypassType Type,
	_In_ LPSTR lpCommand
);