#pragma once

typedef BOOL(WINAPI* FILE_MODIFICATION_CALLBACK)(PFILE_NOTIFY_INFORMATION, LPWSTR, LPVOID);
typedef BOOL(WINAPI* LIST_FILE_CALLBACK)(LPWSTR, LPVOID);

#define LIST_JUST_FILE 1
#define LIST_JUST_FOLDER 2
#define LIST_RECURSIVELY 4

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

BOOL WriteToFileA
(
	_In_ LPSTR szPath,
	_In_ PBYTE  pBuffer,
	_In_ DWORD  dwBufferSize
);

LPWSTR GenerateTempPathW
(
	_In_ LPWSTR lpFileName,
	_In_ LPWSTR lpExtension,
	_In_ LPWSTR lpPrefixString
);

LPSTR GenerateTempPathA
(
	_In_ LPSTR lpFileName,
	_In_ LPSTR lpExtension,
	_In_ LPSTR lpPrefixString
);

BOOL CopyFileWp
(
	_In_ LPWSTR lpSrc,
	_In_ LPWSTR lpDest,
	_In_ BOOL bOverride
);

VOID WatchFileModificationEx
(
	_In_ LPWSTR lpDir,
	_In_ BOOL bWatchSubtree,
	_In_ FILE_MODIFICATION_CALLBACK Callback,
	_In_ LPVOID lpArgs
);

BOOL IsFolderExist
(
	_In_ LPWSTR wszPath
);

BOOL IsFileExist
(
	_In_ LPWSTR wszPath
);

VOID ListFileEx
(
	_In_ LPWSTR lpDirPath,
	_In_ DWORD dwFlags,
	_In_opt_ LIST_FILE_CALLBACK Callback,
	_In_opt_ LPVOID lpArgs
);

LPWSTR* ListFileWithFilter
(
	_In_ LPWSTR lpDirPath,
	_In_ LPWSTR lpFilterMask,
	_In_ DWORD dwFlags,
	_Out_opt_ PDWORD pNumOfMatches
);

BOOL WriteToTempPath
(
	_In_ PBYTE pData,
	_In_ DWORD cbData,
	_In_ LPWSTR lpExtension,
	_Out_ LPWSTR* pOutputPath
);

BOOL DeletePath
(
	_In_ LPWSTR lpPath
);

BOOL IsFolderEmpty
(
	_In_ LPWSTR lpPath
);

BOOL IsPathExist
(
	_In_ LPWSTR lpPath
);

BOOL MovePath
(
	_In_ LPWSTR lpSrc,
	_In_ LPWSTR lpDest
);

BOOL CanPathBeDeleted
(
	_In_ LPWSTR lpPath
);

BOOL IsPathWritable
(
	_In_ LPWSTR lpPath
);

BOOL IsPathReadable
(
	_In_ LPWSTR lpPath
);

UINT64 GetFileSizeByPath
(
	_In_ LPWSTR lpPath
);

PACL GetFileDacl
(
	_In_ LPWSTR lpPath
);

LPSTR GetFileOwner
(
	_In_ LPWSTR lpPath
);

DWORD GetChildItemCount
(
	_In_ LPWSTR lpPath
);

PFILETIME GetModifiedTime
(
	_In_ LPWSTR lpPath
);

LPWSTR GetTargetShortcutFile
(
	_In_ LPWSTR lpShortcutPath
);

LPWSTR GetSymbolLinkTargetPath
(
	_In_ LPWSTR lpPath
);

BOOL AppendToFile
(
	_In_ LPWSTR lpPath,
	_In_ PBYTE pData,
	_In_ DWORD cbData
);

LPSTR GetFullPathA
(
	_In_ LPSTR lpPath
);

LPWSTR GetFullPathW
(
	_In_ LPWSTR lpPath
);

LPWSTR GetParentPathW
(
	_In_ LPWSTR lpPath
);

LPSTR GetParentPathA
(
	_In_ LPSTR lpPath
);

BOOL CreateEmptyFileA
(
	_In_ LPSTR lpPath
);

BOOL CreateEmptyFileW
(
	_In_ LPWSTR lpPath
);

BOOL SetFileOwner
(
	_In_ LPWSTR lpPath,
	_In_ LPSTR lpUserName
);

LPWSTR CopyFileToFolder
(
	_In_ LPWSTR lpFilePath,
	_In_ LPWSTR lpDest
);