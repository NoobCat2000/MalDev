#pragma once

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