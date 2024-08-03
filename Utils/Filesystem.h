#pragma once

typedef BOOL(WINAPI* FILE_CREATION_CALLBACK)(HANDLE, LPWSTR, LPVOID);

PBYTE ReadFromFile
(
	_In_  LPWSTR wszFilePath,
	_Out_ PDWORD pdwFileSize
);

BOOL WriteToFile
(
	_In_ LPWSTR wszPath,
	_In_ PBYTE  pBuffer,
	_In_ DWORD  dwBufferSize
);

VOID GenerateTempPathW
(
	_In_ LPWSTR lpFileName,
	_In_ LPWSTR lpExtension,
	_In_ LPWSTR lpPrefixString,
	_Out_ LPWSTR* Result
);

BOOL CopyFileWp
(
	_In_ LPWSTR lpSrc,
	_In_ LPWSTR lpDest,
	_In_ BOOL bOverride
);

VOID WatchFileCreationEx
(
	_In_ LPTSTR lpDir,
	_In_ BOOL bWatchSubtree,
	_In_ FILE_CREATION_CALLBACK Callback,
	_In_ LPVOID lpParamters
);

BOOL IsFolderExist
(
	_In_ LPWSTR wszPath
);

BOOL IsFileExist
(
	_In_ LPWSTR wszPath
);