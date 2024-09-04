#pragma once

typedef struct _TOKEN_GROUP_INFO {
	CHAR szName[0x100];
	CHAR szStatus[0x10];
	CHAR szDesc[0x80];
	CHAR szSID[0x40];
	CHAR szType[0x20];
} TOKEN_GROUP_INFO, *PTOKEN_GROUP_INFO;

typedef struct _TOKEN_INFO {
	PTOKEN_GROUP_INFO pGroupsInfo;
	BOOL IsElevated;
	TOKEN_ELEVATION_TYPE ElevationType;
	DWORD dwSession;
	LPSTR lpUserName;
	SID UserSID;
	LPSTR lpIntegrityLevel;
} TOKEN_INFO, *PTOKEN_INFO;

typedef struct _PROCESS_INFO {
	LPSTR lpImageFilePath;
	LPSTR lpCommandLine;
	LPSTR lpCurrentDirectory;
	DWORD dwPID;
	DWORD dwPPID;
	LPSTR lpMitigationDesc;
	LPSTR lpVersion;
	BOOL IsWow64;
} PROCESS_INFO, *PPROCESS_INFO;

BOOL Run
(
	_In_ LPWSTR* Argv,
	_In_ DWORD dwArgc,
	_Out_ PHANDLE phProcess
);

DWORD GetProcessIdByName
(
	_In_ LPWSTR lpProcessName
);

HANDLE CreateProcessAndStealToken
(
	_In_ LPWSTR lpFilePath
);

HANDLE SetTokenWithUiAccess
(
	_In_ HANDLE hToken
);

HANDLE GetUiAccessToken();

NTSTATUS IsProcessElevated
(
	_In_ ULONG ProcessId,
	_Out_ PBOOL Elevated
);

BOOL CreateProcessAndGetOutput
(
	_In_ LPWSTR lpCommandLine,
	_Out_ PBYTE* pOutput,
	_Out_ PDWORD pdwSize
);

BOOL CreateProcessWithDesktop
(
	_In_ LPWSTR lpCommandLine,
	_In_ LPWSTR lpDesktopName
);

BOOL AreProcessesRunning
(
	_In_ LPWSTR* pNameList,
	_In_ DWORD dwCount,
	_In_ DWORD dwMin
);

BOOL CheckForBlackListProcess();

LPSTR GetCurrentProcessUserSID();

LPSTR GetCurrentProcessGroupSID();

LPSTR DescribeProcessMitigation
(
	_In_ HANDLE hProcess
);

PTOKEN_SECURITY_ATTRIBUTES_INFORMATION GetTokenSecurityAttributes
(
	_In_ HANDLE hToken
);

LPVOID GetProcessPebAddr
(
	_In_ HANDLE hProc
);

LPSTR GetProcessCommandLine
(
	_In_ HANDLE hProc
);