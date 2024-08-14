#pragma once

BOOL BypassByOsk
(
	_In_ LPSTR lpCommandLine
);

BOOL MasqueradedDeleteDirectoryFileCOM
(
	_In_ LPWSTR lpFilePath
);

BOOL MasqueradedMoveDirectoryFileCOM
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