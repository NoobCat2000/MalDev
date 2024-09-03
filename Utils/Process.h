#pragma once

#define PH_PROCESS_DEP_ENABLED 0x1
#define PH_PROCESS_DEP_ATL_THUNK_EMULATION_DISABLED 0x2
#define PH_PROCESS_DEP_PERMANENT 0x4

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