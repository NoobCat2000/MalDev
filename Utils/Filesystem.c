#include "pch.h"

BOOL IsFolderExist
(
	_In_ LPWSTR wszPath
)
{
	DWORD dwFileAttr = GetFileAttributesW(wszPath);
	if (dwFileAttr != INVALID_FILE_ATTRIBUTES && (dwFileAttr & FILE_ATTRIBUTE_DIRECTORY)) {
		return TRUE;
	}

	return FALSE;
}

BOOL IsFileExist
(
	_In_ LPWSTR wszPath
)
{
	DWORD dwFileAttr = GetFileAttributesW(wszPath);
	if (dwFileAttr != INVALID_FILE_ATTRIBUTES && !(dwFileAttr & FILE_ATTRIBUTE_DIRECTORY)) {
		return TRUE;
	}

	return FALSE;
}

PBYTE ReadFromFile
(
	_In_  LPWSTR wszFilePath,
	_Out_ PDWORD pdwFileSize
)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	PBYTE pResult = NULL;
	DWORD dwFileSize = 0;
	DWORD dwNumberOfBytesRead = 0;

	hFile = CreateFileW(wszFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		goto CLEANUP;
	}

	dwFileSize = GetFileSize(hFile, NULL);
	pResult = ALLOC(dwFileSize + 1);
	if (pResult == NULL) {
		goto CLEANUP;
	}

	if (!ReadFile(hFile, pResult, dwFileSize, &dwNumberOfBytesRead, NULL)) {
		goto CLEANUP;
	}

	if (pdwFileSize != NULL) {
		*pdwFileSize = dwFileSize;
	}

CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	return pResult;
}

BOOL WriteToFile
(
	_In_ LPWSTR wszPath,
	_In_ PBYTE  pBuffer,
	_In_ DWORD  dwBufferSize
)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BOOL bResult = FALSE;
	DWORD dwNumberOfBytesWritten = 0;

	hFile = CreateFileW(wszPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		goto CLEANUP;
	}

	if (!WriteFile(hFile, pBuffer, dwBufferSize, &dwNumberOfBytesWritten, NULL)) {
		goto CLEANUP;
	}

	bResult = TRUE;

CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	return bResult;
}

VOID GenerateTempPathW
(
	_In_ LPWSTR lpFileName,
	_In_ LPWSTR lpExtension,
	_In_ LPWSTR lpPrefixString,
	_Out_ LPWSTR* Result
)
{
	WCHAR wszTempPath[MAX_PATH];
	WCHAR wszTempName[0x100];

	GetTempPathW(MAX_PATH, wszTempPath);
	*Result = ALLOC(MAX_PATH * sizeof(WCHAR));
	if (lpFileName != NULL) {
		wnsprintfW(*Result, MAX_PATH, L"%lls%lls", wszTempPath, lpFileName);
	}
	else {
		GetTempFileNameW(wszTempPath, lpPrefixString, 0, *Result);
		StrCatBuffW(*Result, lpExtension, MAX_PATH);
	}
}

//DWORD CreateDirectoryWp
//(
//	_In_ LPWSTR lpPath
//)
//{
//	SHCreateDirectory(NULL, )
//}

BOOL CopyFileWp
(
	_In_ LPWSTR lpSrc,
	_In_ LPWSTR lpDest,
	_In_ BOOL bOverride
)
{
	WCHAR wszFullDestPath[MAX_PATH];
	LPWSTR lpExtension = NULL;
	BOOL bIsDirectory = FALSE;
	LPWSTR lpDestFileName = NULL;
	
	GetFullPathNameW(lpDest, MAX_PATH, wszFullDestPath, NULL);
	lpExtension = PathFindExtensionW(wszFullDestPath);
	if (lpExtension[0] == L'.') {
		if (!bOverride && PathFileExistsW(wszFullDestPath)) {
			return ERROR_SUCCESS;
		}

		lpDestFileName = PathFindFileNameW(wszFullDestPath);
		lpDestFileName[-1] = L'\0';
	}
	else {
		bIsDirectory = TRUE;
	}

	wprintf(L"%lls\n", wszFullDestPath);
	SHCreateDirectory(NULL, wszFullDestPath);
	if (bIsDirectory) {
		if (wszFullDestPath[lstrlenW(wszFullDestPath) - 1] != L'\\') {
			StrCatW(wszFullDestPath, L"\\");
		}

		StrCatW(wszFullDestPath, PathFindFileNameW(lpSrc));
	}
	else {
		lpDestFileName[-1] = L'\\';
	}

	wprintf(L"%lls\n", wszFullDestPath);
	return CopyFileW(lpSrc, wszFullDestPath, FALSE);
}

//VOID WatchFileCreation
//(
//	_In_ LPTSTR lpDir,
//	_In_ BOOL bWatchSubTree,
//	_In_ FILE_CREATION_CALLBACK CallBack
//)
//{
//	DWORD dwWaitStatus;
//	HANDLE dwChangeHandle = INVALID_HANDLE_VALUE;
//	TCHAR lpFile[_MAX_FNAME];
//	TCHAR lpExt[_MAX_EXT];
//
//	dwChangeHandle = FindFirstChangeNotificationW(lpDir, bWatchSubTree, FILE_NOTIFY_CHANGE_CREATION);
//	if (dwChangeHandle == INVALID_HANDLE_VALUE) {
//		goto END;
//	}
//
//	do {
//		dwWaitStatus = WaitForSingleObject(dwChangeHandle, INFINITE);
//		if (dwWaitStatus != WAIT_OBJECT_0) {
//			break;
//		}
//
//	} while (FindNextChangeNotification(dwChangeHandle));
//
//END:
//
//}

VOID WatchFileCreationEx
(
	_In_ LPWSTR lpDir,
	_In_ BOOL bWatchSubtree,
	_In_ FILE_CREATION_CALLBACK Callback,
	_In_ LPVOID lpParamters
)
{
	HANDLE hDir = INVALID_HANDLE_VALUE;
	OVERLAPPED Overlapped;
	CHAR ChangeBuffer[0x1000];
	DWORD dwBytesReturned = 0;
	DWORD dwResult = 0;
	DWORD dwBytesTransferred = 0;
	PFILE_NOTIFY_INFORMATION pNotifyInfo;
	DWORD dwFileNameLength = 0;
	WCHAR wszEntireFilePath[MAX_PATH];

	hDir = CreateFileW(lpDir, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
	if (hDir == INVALID_HANDLE_VALUE) {
		goto END;
	}

	Overlapped.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
	ZeroMemory(ChangeBuffer, sizeof(ChangeBuffer));
	if (!ReadDirectoryChangesW(hDir, ChangeBuffer, sizeof(ChangeBuffer), bWatchSubtree, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE, &dwBytesReturned, &Overlapped, NULL)) {
		goto END;
	}

	while (TRUE) {
		dwResult = WaitForSingleObject(Overlapped.hEvent, INFINITE);
		if (dwResult == WAIT_OBJECT_0) {
			GetOverlappedResult(hDir, &Overlapped, &dwBytesTransferred, FALSE);
			pNotifyInfo = (PFILE_NOTIFY_INFORMATION)ChangeBuffer;
			dwFileNameLength = pNotifyInfo->FileNameLength / sizeof(WCHAR);
			while (TRUE) {
				switch (pNotifyInfo->Action) {
				case FILE_ACTION_ADDED:
					pNotifyInfo->FileName[dwFileNameLength] = L'\0';
					StringCchPrintfW(wszEntireFilePath, MAX_PATH, L"%lls\\%lls", lpDir, pNotifyInfo->FileName);
					Callback(hDir, wszEntireFilePath, lpParamters);
					break;
				default:
					break;
				}

				if (pNotifyInfo->NextEntryOffset) {
					pNotifyInfo += pNotifyInfo->NextEntryOffset;
					if (pNotifyInfo >= &ChangeBuffer[sizeof(ChangeBuffer)]) {
						break;
					}
				}
				else {
					break;
				}
			}

			ZeroMemory(ChangeBuffer, sizeof(ChangeBuffer));
			if (!ReadDirectoryChangesW(hDir, ChangeBuffer, sizeof(ChangeBuffer), bWatchSubtree, FILE_NOTIFY_CHANGE_CREATION, NULL, &Overlapped, NULL)) {
				break;
			}
		}
	}
END:
	if (hDir != INVALID_HANDLE_VALUE) {
		CloseHandle(hDir);
	}
}

VOID ListFileEx
(
	_In_ LPWSTR lpDirPath,
	_In_ DWORD dwFlags,
	_In_opt_ LIST_FILE_CALLBACK Callback,
	_In_opt_ LPVOID lpArgs
)
{
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW FileData;
	LPWSTR lpMaskedPath = NULL;
	LPWSTR lpNewPath = NULL;
	DWORD cbNewPath = 0;
	DWORD cbDirPath = lstrlenW(lpDirPath);
	BOOL IsFolder = FALSE;

	RtlSecureZeroMemory(&FileData, sizeof(FileData));
	lpMaskedPath = DuplicateStrW(lpDirPath, 3);
	if (lpDirPath[cbDirPath - 1] != L'\\') {
		lstrcatW(lpMaskedPath, L"\\");
	}

	lstrcatW(lpMaskedPath, L"*");
	hFind = FindFirstFileW(lpMaskedPath, &FileData);
	if (hFind == INVALID_HANDLE_VALUE) {
		goto CLEANUP;
	}

	do {
		cbNewPath = cbDirPath + 1 + lstrlenW(FileData.cFileName);
		if (lpNewPath == NULL) {
			lpNewPath = ALLOC((cbNewPath + 1) * sizeof(WCHAR));
		}
		else {
			lpNewPath = REALLOC(lpNewPath, (cbNewPath + 1) * sizeof(WCHAR));
		}

		swprintf_s(lpNewPath, cbNewPath + 1, L"%lls\\%lls", lpDirPath, FileData.cFileName);
		if (!StrCmpW(FileData.cFileName, L".") || !StrCmpW(FileData.cFileName, L"..")) {
			continue;
		}
		else {
			IsFolder = (FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
			if ((dwFlags & LIST_RECURSIVELY) && IsFolder) {
				ListFileEx(lpNewPath, dwFlags, Callback, lpArgs);
			}

			if ((dwFlags & LIST_JUST_FILE) && IsFolder) {
				continue;
			}

			if ((dwFlags & LIST_JUST_FOLDER) && !IsFolder) {
				continue;
			}

			if (Callback(lpNewPath, lpArgs)) {
				break;
			}
		}
	} while (FindNextFileW(hFind, &FileData));
CLEANUP:
	if (hFind != INVALID_HANDLE_VALUE) {
		FindClose(hFind);
	}

	if (lpMaskedPath != NULL) {
		FREE(lpMaskedPath);
	}

	if (lpNewPath != NULL) {
		FREE(lpNewPath);
	}

	return;
}

LPWSTR* ListFileWithFilter
(
	_In_ LPWSTR lpDirPath,
	_In_ LPWSTR lpFilterMask,
	_In_ DWORD dwFlags,
	_Out_opt_ PDWORD pNumOfMatches
)
{
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW FileData;
	LPWSTR lpMaskedPath = NULL;
	LPWSTR lpNewPath = NULL;
	DWORD cbNewPath = 0;
	DWORD cbDirPath = lstrlenW(lpDirPath);
	BOOL IsFolder = FALSE;
	LPWSTR* lpResult = NULL;
	DWORD dwCapacity = 0;
	DWORD dwCounter = 0;

	RtlSecureZeroMemory(&FileData, sizeof(FileData));
	lpMaskedPath = DuplicateStrW(lpDirPath, lstrlenW(lpFilterMask) + 2);
	if (lpDirPath[cbDirPath - 1] != L'\\') {
		lstrcatW(lpMaskedPath, L"\\");
	}

	lstrcatW(lpMaskedPath, lpFilterMask);
	hFind = FindFirstFileW(lpMaskedPath, &FileData);
	if (hFind == INVALID_HANDLE_VALUE) {
		wprintf(L"FindFirstFileW failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	lpResult = ALLOC(sizeof(LPWSTR) * 10);
	dwCapacity = 10;
	do {
		cbNewPath = cbDirPath + 1 + lstrlenW(FileData.cFileName);
		if (lpNewPath == NULL) {
			lpNewPath = ALLOC((cbNewPath + 1) * sizeof(WCHAR));
		}
		else {
			lpNewPath = REALLOC(lpNewPath, (cbNewPath + 1) * sizeof(WCHAR));
		}

		swprintf_s(lpNewPath, cbNewPath + 1, L"%lls\\%lls", lpDirPath, FileData.cFileName);
		if (!StrCmpW(FileData.cFileName, L".") || !StrCmpW(FileData.cFileName, L"..")) {
			continue;
		}
		else {
			IsFolder = (FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
			if ((dwFlags & LIST_JUST_FILE) && IsFolder) {
				continue;
			}

			if ((dwFlags & LIST_JUST_FOLDER) && !IsFolder) {
				continue;
			}

			lpResult[dwCounter++] = DuplicateStrW(lpNewPath, 0);
			if (dwCounter >= dwCapacity) {
				dwCapacity = dwCounter * 2;
				lpResult = REALLOC(lpResult, dwCapacity * sizeof(LPWSTR));
			}
		}
	} while (FindNextFileW(hFind, &FileData));

	if (pNumOfMatches != NULL) {
		*pNumOfMatches = dwCounter;
	}

	lpResult = REALLOC(lpResult, dwCounter * sizeof(LPWSTR));
CLEANUP:
	if (hFind != INVALID_HANDLE_VALUE) {
		FindClose(hFind);
	}

	if (lpMaskedPath != NULL) {
		FREE(lpMaskedPath);
	}

	if (lpNewPath != NULL) {
		FREE(lpNewPath);
	}

	return lpResult;
}

BOOL WriteToTempPath
(
	_In_ PBYTE pData,
	_In_ DWORD cbData,
	_In_ LPWSTR lpExtension,
	_Out_ LPWSTR* pOutputPath
)
{
	WCHAR wszPath[MAX_PATH + 1];
	BOOL bResult = FALSE;
	LPSTR lpRandStr = NULL;
	LPWSTR lpRandName = NULL;

	lpRandStr = GenRandomStr(10);
	lpRandName = ConvertCharToWchar(lpRandStr);

	RtlSecureZeroMemory(wszPath, sizeof(wszPath));
	GetTempPathW(MAX_PATH + 1, wszPath);
	lstrcatW(wszPath, lpRandName);
	lstrcatW(wszPath, L".");
	lstrcatW(wszPath, lpExtension);
	wprintf(L"wszPath: %lls\n", wszPath);
	bResult = WriteToFile(wszPath, pData, cbData);
	if (pOutputPath != NULL) {
		*pOutputPath = DuplicateStrW(wszPath, 0);
	}

CLEANUP:
	if (lpRandStr != NULL) {
		FREE(lpRandStr);
	}

	if (lpRandName != NULL) {
		FREE(lpRandName);
	}

	return bResult;
}