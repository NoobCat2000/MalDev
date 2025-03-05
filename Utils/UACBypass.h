#pragma once

BOOL BypassByOsk
(
	_In_ LPSTR lpCommandLine
);

BOOL MasqueradedDeleteDirectoryFileCOM
(
	_In_ LPWSTR lpFilePath
);

BOOL MasqueradedMoveCopyDirectoryFileCOM
(
	_In_ LPWSTR lpSrcFileName,
	_In_ LPWSTR lpDestPath,
	_In_ BOOL IsMove
);

BOOL IeAddOnInstallMethod
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer
);

VOID MasqueradeProcessPath
(
	_In_ LPWSTR lpNewPath,
	_In_ BOOL Restore,
	_Inout_opt_ LPWSTR* pBackupPath
);

VOID InitUnicodeString
(
	_Out_ PUNICODE_STRING DestinationString,
	_In_opt_z_ LPWSTR SourceString
);

BOOL MasqueradedCreateDirectoryFileCOM
(
	_In_ LPWSTR lpFilePath
);