#include "pch.h"

BOOL IsFolderExist
(
	_In_ LPWSTR lpPath
)
{
	DWORD dwFileAttr = GetFileAttributesW(lpPath);
	if (dwFileAttr != INVALID_FILE_ATTRIBUTES && (dwFileAttr & FILE_ATTRIBUTE_DIRECTORY)) {
		return TRUE;
	}

	return FALSE;
}

BOOL IsFileExist
(
	_In_ LPWSTR lpPath
)
{
	DWORD dwFileAttr = GetFileAttributesW(lpPath);
	if (dwFileAttr != INVALID_FILE_ATTRIBUTES && !(dwFileAttr & FILE_ATTRIBUTE_DIRECTORY)) {
		return TRUE;
	}

	return FALSE;
}

BOOL IsPathExist
(
	_In_ LPWSTR lpPath
)
{
	if (IsFileExist(lpPath)) {
		return TRUE;
	}

	if (IsFolderExist(lpPath)) {
		return TRUE;
	}

	return FALSE;
}

BOOL AppendToFile
(
	_In_ LPWSTR lpPath,
	_In_ PBYTE pData,
	_In_ DWORD cbData
)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BOOL bResult = FALSE;
	DWORD dwNumberOfBytesWritten = 0;

	hFile = CreateFileW(lpPath, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		goto CLEANUP;
	}

	if (!WriteFile(hFile, pData, cbData, &dwNumberOfBytesWritten, NULL)) {
		goto CLEANUP;
	}

	bResult = TRUE;

CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	return bResult;
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
		LOG_ERROR("CreateFileW", GetLastError());
		goto CLEANUP;
	}

	dwFileSize = GetFileSize(hFile, NULL);
	pResult = ALLOC(dwFileSize + 1);
	if (pResult == NULL) {
		goto CLEANUP;
	}

	if (!ReadFile(hFile, pResult, dwFileSize, &dwNumberOfBytesRead, NULL)) {
		LOG_ERROR("ReadFile", GetLastError());
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

BOOL WriteToFileA
(
	_In_ LPSTR szPath,
	_In_ PBYTE  pBuffer,
	_In_ DWORD  dwBufferSize
)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BOOL bResult = FALSE;
	DWORD dwNumberOfBytesWritten = 0;

	hFile = CreateFileA(szPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
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

LPWSTR GenerateTempPathW
(
	_In_ LPWSTR lpFileName,
	_In_ LPWSTR lpExtension,
	_In_ LPWSTR lpPrefixString
)
{
	WCHAR wszTempPath[MAX_PATH];
	WCHAR wszTempName[0x100];
	LPWSTR lpResult = NULL;

	GetTempPathW(MAX_PATH, wszTempPath);
	lpResult = ALLOC(MAX_PATH * sizeof(WCHAR));
	if (lpFileName != NULL) {
		wnsprintfW(lpResult, MAX_PATH, L"%s%s", wszTempPath, lpFileName);
	}
	else {
		GetTempFileNameW(wszTempPath, lpPrefixString, 0, lpResult);
		DeleteFileW(lpResult);
		if (lpExtension != NULL) {
			lstrcatW(lpResult, lpExtension);
		}
	}

	return lpResult;
}

LPSTR GenerateTempPathA
(
	_In_ LPSTR lpFileName,
	_In_ LPSTR lpExtension,
	_In_ LPSTR lpPrefixString
)
{
	CHAR szTempPath[MAX_PATH];
	CHAR szTempName[0x100];
	LPSTR lpResult = NULL;

	GetTempPathA(_countof(szTempPath), szTempPath);
	lpResult = ALLOC(MAX_PATH);
	if (lpFileName != NULL) {
		wsprintfA(lpResult, "%s%s", szTempPath, lpFileName);
	}
	else {
		GetTempFileNameA(szTempPath, lpPrefixString, 0, lpResult);
		DeleteFileA(lpResult);
		if (lpExtension) {
			lstrcatA(lpResult, lpExtension);
		}
	}

	return lpResult;
}

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

	return CopyFileW(lpSrc, wszFullDestPath, FALSE);
}

BOOL IsFolderEmpty
(
	_In_ LPWSTR lpPath
)
{
	BOOL Result = FALSE;
	LPWSTR lpMaskedPath = NULL;
	DWORD cbDirPath = 0;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW FindData;
	DWORD dwLastError = ERROR_SUCCESS;

	SecureZeroMemory(&FindData, sizeof(FindData));
	if (!IsFolderExist(lpPath)) {
		goto CLEANUP;
	}

	cbDirPath = lstrlenW(lpPath);
	lpMaskedPath = DuplicateStrW(lpPath, 3);
	if (lpPath[cbDirPath - 1] != L'\\') {
		lstrcatW(lpMaskedPath, L"\\");
	}

	lstrcatW(lpMaskedPath, L"*");
	hFind = FindFirstFileW(lpMaskedPath, &FindData);
	if (hFind == INVALID_HANDLE_VALUE) {
		dwLastError = GetLastError();
		if (dwLastError != ERROR_FILE_NOT_FOUND) {
			LOG_ERROR("FindFirstFileW", GetLastError());
		}

		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	FREE(lpMaskedPath);
	if (hFind != INVALID_HANDLE_VALUE) {
		CloseHandle(hFind);
	}

	return Result;
}

BOOL MakeDirEx
(
	_In_ LPWSTR lpPath
)
{

}

BOOL DeletePath
(
	_In_ LPWSTR lpPath
)
{
	SHFILEOPSTRUCTW ShFileStruct;
	BOOL Result = FALSE;
	DWORD dwErrorCode = 0;
	LPWSTR lpLastName = NULL;

	SecureZeroMemory(&ShFileStruct, sizeof(ShFileStruct));
	ShFileStruct.wFunc = FO_DELETE;
	ShFileStruct.pFrom = DuplicateStrW(lpPath, 2);
	ShFileStruct.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_NOERRORUI | FOF_NO_UI | FOF_SILENT;
	dwErrorCode = SHFileOperationW(&ShFileStruct);
	if (dwErrorCode != 0) {
		LOG_ERROR("SHFileOperationW", dwErrorCode);
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	FREE(ShFileStruct.pFrom);
	return Result;
}

BOOL MovePath
(
	_In_ LPWSTR lpSrc,
	_In_ LPWSTR lpDest
)
{
	SHFILEOPSTRUCTW ShFileStruct;
	BOOL Result = FALSE;

	SecureZeroMemory(&ShFileStruct, sizeof(ShFileStruct));
	ShFileStruct.wFunc = FO_MOVE;
	ShFileStruct.pFrom = DuplicateStrW(lpSrc, 2);
	ShFileStruct.pTo = DuplicateStrW(lpDest, 2);
	ShFileStruct.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_NOERRORUI | FOF_NO_UI | FOF_SILENT;
	if (SHFileOperationW(&ShFileStruct)) {
		LOG_ERROR("SHFileOperationW", GetLastError());
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	FREE(ShFileStruct.pFrom);
	FREE(ShFileStruct.pTo);
	return Result;
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

VOID WatchFileModificationEx
(
	_In_ LPWSTR lpDir,
	_In_ BOOL bWatchSubtree,
	_In_ FILE_MODIFICATION_CALLBACK Callback,
	_In_ LPVOID lpArgs
)
{
	HANDLE hDir = INVALID_HANDLE_VALUE;
	OVERLAPPED Overlapped;
	CHAR ChangeBuffer[0x4000];
	DWORD dwBytesReturned = 0;
	DWORD dwResult = 0;
	DWORD dwBytesTransferred = 0;
	PFILE_NOTIFY_INFORMATION pNotifyInfo;
	DWORD dwNotifyFlag = FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_LAST_WRITE;
	LPWSTR lpTemp = NULL;

	SecureZeroMemory(ChangeBuffer, sizeof(ChangeBuffer));
	SecureZeroMemory(&Overlapped, sizeof(Overlapped));
	hDir = CreateFileW(lpDir, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
	if (hDir == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateFileW", GetLastError());
		goto CLEANUP;
	}

	Overlapped.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
	if (!ReadDirectoryChangesW(hDir, ChangeBuffer, sizeof(ChangeBuffer), bWatchSubtree, dwNotifyFlag, &dwBytesReturned, &Overlapped, NULL)) {
		LOG_ERROR("ReadDirectoryChangesW", GetLastError());
		goto CLEANUP;
	}

	while (TRUE) {
		dwResult = WaitForSingleObject(Overlapped.hEvent, INFINITE);
		if (dwResult == WAIT_OBJECT_0) {
			GetOverlappedResult(hDir, &Overlapped, &dwBytesTransferred, FALSE);
			pNotifyInfo = (PFILE_NOTIFY_INFORMATION)ChangeBuffer;
			while (TRUE) {
				if (pNotifyInfo->Action == FILE_ACTION_ADDED || pNotifyInfo->Action == FILE_ACTION_MODIFIED) {
					lpTemp = DuplicateStrW(lpDir, lstrlenW(pNotifyInfo->FileName) + 10);
					if (lpTemp[lstrlenW(lpTemp) - 1] != L'\\') {
						lstrcatW(lpTemp, L"\\");
					}

					lstrcatW(lpTemp, pNotifyInfo->FileName);
					if (Callback(pNotifyInfo, lpTemp, lpArgs)) {
						goto CLEANUP;
					}
				}

				if (pNotifyInfo->NextEntryOffset) {
					pNotifyInfo += pNotifyInfo->NextEntryOffset;
					if (pNotifyInfo < &ChangeBuffer[sizeof(ChangeBuffer)]) {
						continue;
					}
				}

				break;
			}

			SecureZeroMemory(ChangeBuffer, sizeof(ChangeBuffer));
			if (!ReadDirectoryChangesW(hDir, ChangeBuffer, sizeof(ChangeBuffer), bWatchSubtree, dwNotifyFlag, NULL, &Overlapped, NULL)) {
				break;
			}
		}
	}
CLEANUP:
	if (Overlapped.hEvent != NULL) {
		CloseHandle(Overlapped.hEvent);
	}

	if (hDir != INVALID_HANDLE_VALUE) {
		CloseHandle(hDir);
	}

	return;
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
	DWORD cbDirPath = 0;
	BOOL IsFolder = FALSE;
	LPWSTR lpClonePath = NULL;

	SecureZeroMemory(&FileData, sizeof(FileData));
	lpClonePath = DuplicateStrW(lpDirPath, 0);
	cbDirPath = lstrlenW(lpClonePath);
	if (lpClonePath[cbDirPath - 1] == L'\\') {
		lpClonePath[cbDirPath - 1] = L'\0';
		cbDirPath--;
	}

	lpMaskedPath = DuplicateStrW(lpClonePath, 3);
	lstrcatW(lpMaskedPath, L"\\");
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

		wsprintfW(lpNewPath, L"%s\\%s", lpClonePath, FileData.cFileName);
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

			if (Callback != NULL) {
				if (Callback(lpNewPath, lpArgs)) {
					break;
				}
			}
		}
	} while (FindNextFileW(hFind, &FileData));
CLEANUP:
	if (hFind != INVALID_HANDLE_VALUE) {
		FindClose(hFind);
	}

	FREE(lpMaskedPath);
	FREE(lpNewPath);
	FREE(lpClonePath);

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
		LOG_ERROR("FindFirstFileW", GetLastError());
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

		wsprintfW(lpNewPath, L"%s\\%s", lpDirPath, FileData.cFileName);
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

	FREE(lpMaskedPath);
	FREE(lpNewPath);

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

	lpRandStr = GenRandomStrA(10);
	lpRandName = ConvertCharToWchar(lpRandStr);

	RtlSecureZeroMemory(wszPath, sizeof(wszPath));
	GetTempPathW(MAX_PATH + 1, wszPath);
	lstrcatW(wszPath, lpRandName);
	lstrcatW(wszPath, L".");
	lstrcatW(wszPath, lpExtension);
	bResult = WriteToFile(wszPath, pData, cbData);
	if (pOutputPath != NULL) {
		*pOutputPath = DuplicateStrW(wszPath, 0);
	}

CLEANUP:
	FREE(lpRandStr);
	FREE(lpRandName);

	return bResult;
}

BOOL CanPathBeDeleted
(
	_In_ LPWSTR lpPath
)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BOOL Result = FALSE;

	hFile = CreateFileW(lpPath, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateFileW", GetLastError());
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	return Result;
}

BOOL IsPathWritable
(
	_In_ LPWSTR lpPath
)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BOOL Result = FALSE;

	hFile = CreateFileW(lpPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateFileW", GetLastError());
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	return Result;
}

BOOL IsPathReadable
(
	_In_ LPWSTR lpPath
)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BOOL Result = FALSE;

	hFile = CreateFileW(lpPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateFileW", GetLastError());
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	return Result;
}

UINT64 GetFileSizeByPath
(
	_In_ LPWSTR lpPath
)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	UINT64 uResult = 0;
	DWORD dwFileSize = 0;
	DWORD dwFileSizeHigh = 0;

	hFile = CreateFileW(lpPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateFileW", GetLastError());
		goto CLEANUP;
	}

	dwFileSize = GetFileSize(hFile, &dwFileSizeHigh);
	uResult = dwFileSize;
	if (dwFileSizeHigh > 0) {
		uResult |= (dwFileSizeHigh << sizeof(DWORD));
	}

CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	return uResult;
}

PACL GetFileDacl
(
	_In_ LPWSTR lpPath
)
{
	HANDLE hFile = NULL;
	PSECURITY_DESCRIPTOR pTemp = NULL;
	BOOL DaclPresent = FALSE;
	BOOL DaclDefaulted = FALSE;
	PACL pDacl = NULL;
	PACL pResult = NULL;
	LPWSTR lpConvertedPath = NULL;
	UNICODE_STRING NtFileName;
	RTL_RELATIVE_NAME_U RelativeName;
	HANDLE ContainingDirectory = NULL;
	LPWSTR lpSavedBuffer = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS Status = STATUS_SUCCESS;
	IO_STATUS_BLOCK IoStatusBlock;
	FILE_ATTRIBUTE_TAG_INFORMATION FileAttribute;

	SecureZeroMemory(&RelativeName, sizeof(RelativeName));
	SecureZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	SecureZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	SecureZeroMemory(&FileAttribute, sizeof(FileAttribute));
	if (!RtlDosPathNameToRelativeNtPathName_U(lpPath, &NtFileName, NULL, &RelativeName)) {
		LOG_ERROR("RtlDosPathNameToRelativeNtPathName_U", GetLastError());
		goto CLEANUP;
	}

	if (RelativeName.RelativeName.Length > 0) {
		ContainingDirectory = RelativeName.ContainingDirectory;
		lpSavedBuffer = NtFileName.Buffer;
		memcpy(&NtFileName, &RelativeName.RelativeName, sizeof(UNICODE_STRING));
	}
	else {
		RelativeName.ContainingDirectory = NULL;
	}

	ObjectAttributes.ObjectName = &NtFileName;
	ObjectAttributes.RootDirectory = ContainingDirectory;
	ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	ObjectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
	Status = NtOpenFile(&hFile, READ_CONTROL | FILE_READ_ATTRIBUTES, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_REPARSE_POINT);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("NtOpenFile", GetLastError());
		goto CLEANUP;
	}

	Status = NtQueryInformationFile(hFile, &IoStatusBlock, &FileAttribute, sizeof(FileAttribute), FileAttributeTagInformation);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("NtQueryInformationFile", GetLastError());
		goto CLEANUP;
	}

	if ((FileAttribute.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && FileAttribute.ReparseTag == IO_REPARSE_TAG_SYMLINK) {
		NtClose(hFile);
		Status = NtOpenFile(&hFile, READ_CONTROL, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
		if (!NT_SUCCESS(Status)) {
			LOG_ERROR("NtOpenFile", GetLastError());
			goto CLEANUP;
		}
	}

	RtlReleaseRelativeName(&RelativeName);
	if (GetSecurityInfo(hFile, SE_FILE_OBJECT, ACCESS_FILTER_SECURITY_INFORMATION | PROCESS_TRUST_LABEL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pTemp) != ERROR_SUCCESS) {
		LOG_ERROR("GetSecurityInfo", GetLastError());
		goto CLEANUP;
	}

	if (!GetSecurityDescriptorDacl(pTemp, &DaclPresent, &pDacl, &DaclDefaulted)) {
		LOG_ERROR("GetSecurityDescriptorDacl", GetLastError());
		goto CLEANUP;
	}

	if (DaclPresent) {
		pResult = ALLOC(pDacl->AclSize);
		memcpy(pResult, pDacl, pDacl->AclSize);
	}

CLEANUP:
	if (hFile != NULL) {
		NtClose(hFile);
	}

	if (pTemp != NULL) {
		LocalFree(pTemp);
	}

	FREE(lpSavedBuffer);

	return pResult;
}

LPSTR GetFileOwner
(
	_In_ LPWSTR lpPath
)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	LPSTR lpResult = NULL;
	PSID pSidOwner = NULL;
	PSECURITY_DESCRIPTOR pSecurityDescriptor = NULL;
	DWORD dwErrorCode = 0;

	hFile = CreateFileW(lpPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateFileW", GetLastError());
		goto CLEANUP;
	}

	dwErrorCode = GetSecurityInfo(hFile, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pSidOwner, NULL, NULL, NULL, &pSecurityDescriptor);
	if (dwErrorCode != ERROR_SUCCESS) {
		LOG_ERROR("GetSecurityInfo", GetLastError());
		goto CLEANUP;
	}

	lpResult = LookupNameOfSid(pSidOwner, TRUE);
CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	if (pSecurityDescriptor != NULL) {
		LocalFree(pSecurityDescriptor);
	}

	return lpResult;
}

PFILETIME GetModifiedTime
(
	_In_ LPWSTR lpPath
)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	PFILETIME pResult = NULL;

	hFile = CreateFileW(lpPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateFileW", GetLastError());
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(FILETIME));
	if (!GetFileTime(hFile, NULL, NULL, pResult)) {
		LOG_ERROR("GetFileTime", GetLastError());
		FREE(pResult);
		pResult = NULL;
		goto CLEANUP;
	}

CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	return pResult;
}

DWORD GetChildItemCount
(
	_In_ LPWSTR lpPath
)
{
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW FileData;
	LPWSTR lpMaskedPath = NULL;
	DWORD cbDirPath = lstrlenW(lpPath);
	BOOL IsFolder = FALSE;
	DWORD dwResult = 0;

	RtlSecureZeroMemory(&FileData, sizeof(FileData));
	lpMaskedPath = DuplicateStrW(lpPath, 2);
	if (lpPath[cbDirPath - 1] != L'\\') {
		lstrcatW(lpMaskedPath, L"\\");
	}

	lstrcatW(lpMaskedPath, L"*");
	hFind = FindFirstFileW(lpMaskedPath, &FileData);
	if (hFind == INVALID_HANDLE_VALUE) {
		LOG_ERROR("FindFirstFileW", GetLastError());
		goto CLEANUP;
	}

	do {
		if (!StrCmpW(FileData.cFileName, L".") || !StrCmpW(FileData.cFileName, L"..")) {
			continue;
		}
		else {
			dwResult++;
		}
	} while (FindNextFileW(hFind, &FileData));

CLEANUP:
	if (hFind != INVALID_HANDLE_VALUE) {
		FindClose(hFind);
	}

	FREE(lpMaskedPath);

	return dwResult;
}

LPWSTR GetSymbolLinkTargetPath
(
	_In_ LPWSTR lpPath
)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	LPWSTR lpResult = NULL;
	DWORD cchResult = MAX_PATH;
	DWORD dwFileAttributes = 0;
	DWORD dwReturnedLength = 0;
	DWORD dwErrorCode = ERROR_SUCCESS;

	dwFileAttributes = GetFileAttributesW(lpPath);
	if ((dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != FILE_ATTRIBUTE_REPARSE_POINT) {
		return NULL;
	}

	hFile = CreateFileW(lpPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateFileW", GetLastError());
		goto CLEANUP;
	}

	lpResult = ALLOC(sizeof(WCHAR) * cchResult);
	dwReturnedLength = GetFinalPathNameByHandleW(hFile, lpResult, cchResult, FILE_NAME_OPENED);
	if (dwReturnedLength == 0) {
		LOG_ERROR("GetFinalPathNameByHandleW", GetLastError());
		FREE(lpResult);
		lpResult = NULL;
		goto CLEANUP;
	}
	else if (dwReturnedLength >= cchResult) {
		cchResult = dwReturnedLength + 1;
		lpResult = REALLOC(lpResult, cchResult * sizeof(WCHAR));
		GetFinalPathNameByHandleW(hFile, lpResult, cchResult, 0);
	}

CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	return lpResult;
}

LPWSTR GetTargetShortcutFile
(
	_In_ LPWSTR lpShortcutPath
)
{
	IShellLinkW* pShellLink = NULL;
	IPersistFile* pPersistFile = NULL;
	HRESULT hRes = S_FALSE;
	HRESULT hResultInit = S_FALSE;
	LPWSTR lpResult = NULL;
	WCHAR wszRawPath[MAX_PATH];
	WIN32_FIND_DATAW FindData;
	CLSID CLSID_ShellLink = { 0x21401, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
	IID IID_IShellLinkW = { 0x214F9, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
	IID IID_IPersistFile = { 0x10B, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };

	SecureZeroMemory(&FindData, sizeof(FindData));
	SecureZeroMemory(wszRawPath, sizeof(wszRawPath));
	hResultInit = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	hRes = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (LPVOID*)&pShellLink);
	if (!SUCCEEDED(hRes)) {
		LOG_ERROR("GetFinalPathNameByHandleW", hRes);
		goto CLEANUP;
	}

	hRes = pShellLink->lpVtbl->QueryInterface(pShellLink, &IID_IPersistFile, (void**)&pPersistFile);
	if (!SUCCEEDED(hRes)) {
		LOG_ERROR("pShellLink->QueryInterface", hRes);
		goto CLEANUP;
	}

	hRes = pPersistFile->lpVtbl->Load(pPersistFile, lpShortcutPath, STGM_READ);
	if (!SUCCEEDED(hRes)) {
		LOG_ERROR("pPersistFile->Load", hRes);
		goto CLEANUP;
	}

	hRes = pShellLink->lpVtbl->Resolve(pShellLink, NULL, 0);
	if (!SUCCEEDED(hRes)) {
		LOG_ERROR("pShellLink->Resolve", hRes);
		goto CLEANUP;
	}

	hRes = pShellLink->lpVtbl->GetPath(pShellLink, wszRawPath, _countof(wszRawPath), &FindData, SLGP_RAWPATH);
	if (!SUCCEEDED(hRes)) {
		LOG_ERROR("pShellLink->GetPath", hRes);
		FREE(lpResult);
		lpResult = NULL;
		goto CLEANUP;
	}

	lpResult = ALLOC(MAX_PATH * sizeof(WCHAR));
	ExpandEnvironmentStringsW(wszRawPath, lpResult, MAX_PATH);
CLEANUP:
	if (pPersistFile != NULL) {
		pPersistFile->lpVtbl->Release(pPersistFile);
	}

	if (pShellLink != NULL) {
		pShellLink->lpVtbl->Release(pShellLink);
	}

	CoUninitialize();
	return lpResult;
}

LPSTR GetFullPathA
(
	_In_ LPSTR lpPath
)
{
	LPSTR lpResult = NULL;
	DWORD cchResult = MAX_PATH;
	DWORD dwLastError = ERROR_SUCCESS;
	CHAR szCurrentDirectory[MAX_PATH + 1];
	DWORD dwDriveNumber = 0;
	CHAR szTemp[] = "C:\\";

	GetCurrentDirectoryA(_countof(szCurrentDirectory), szCurrentDirectory);
	dwDriveNumber = PathGetDriveNumberA(szCurrentDirectory);
	szTemp[0] = dwDriveNumber + 'A';
	if (!lstrcmpA(szTemp, lpPath)) {
		lpResult = DuplicateStrA(lpPath, 0);
		return lpResult;
	}

	szTemp[2] = '\0';
	if (!lstrcmpA(szTemp, lpPath)) {
		lpResult = DuplicateStrA(lpPath, 0);
		return lpResult;
	}

	lpResult = ALLOC(cchResult + 1);
	cchResult = GetFullPathNameA(lpPath, cchResult + 1, lpResult, NULL);
	dwLastError = GetLastError();
	if (cchResult == 0) {
		FREE(lpResult);
		LOG_ERROR("GetFullPathNameA", dwLastError);
		return NULL;
	}

	if (dwLastError == ERROR_NOT_ENOUGH_MEMORY) {
		lpResult = REALLOC(lpResult, cchResult + 1);
		GetFullPathNameA(lpPath, cchResult + 1, lpResult, NULL);
	}

	return lpResult;
}

LPWSTR GetFullPathW
(
	_In_ LPWSTR lpPath
)
{
	LPWSTR lpResult = NULL;
	DWORD cchResult = MAX_PATH;
	DWORD dwLastError = ERROR_SUCCESS;
	CHAR szCurrentDirectory[MAX_PATH + 1];
	DWORD dwDriveNumber = 0;
	WCHAR wszTemp[] = L"C:\\";

	GetCurrentDirectoryW(_countof(szCurrentDirectory), szCurrentDirectory);
	dwDriveNumber = PathGetDriveNumberW(szCurrentDirectory);
	wszTemp[0] = dwDriveNumber + L'A';
	if (!lstrcmpW(wszTemp, lpPath)) {
		lpResult = DuplicateStrW(lpPath, 0);
		return lpResult;
	}

	wszTemp[2] = L'\0';
	if (!lstrcmpW(wszTemp, lpPath)) {
		lpResult = DuplicateStrW(lpPath, 0);
		return lpResult;
	}

	lpResult = ALLOC((cchResult + 1) * sizeof(WCHAR));
	cchResult = GetFullPathNameW(lpPath, cchResult + 1, lpResult, NULL);
	dwLastError = GetLastError();
	if (cchResult == 0) {
		FREE(lpResult);
		LOG_ERROR("GetFullPathNameW", dwLastError);
		return NULL;
	}

	if (dwLastError == ERROR_NOT_ENOUGH_MEMORY) {
		lpResult = REALLOC(lpResult, (cchResult + 1) * sizeof(WCHAR));
		GetFullPathNameW(lpPath, cchResult + 1, lpResult, NULL);
	}

	return lpResult;
}

LPWSTR GetParentPathW
(
	_In_ LPWSTR lpPath
)
{
	LPWSTR lpFileName = NULL;
	LPWSTR lpResult = NULL;

	lpResult = DuplicateStrW(lpPath, 0);
	lpFileName = PathFindFileNameW(lpResult);
	lpFileName[-1] = L'\0';

	return lpResult;
}

LPSTR GetParentPathA
(
	_In_ LPSTR lpPath
)
{
	LPSTR lpFileName = NULL;
	LPSTR lpResult = NULL;

	lpResult = DuplicateStrA(lpPath, 0);
	lpFileName = PathFindFileNameA(lpResult);
	lpFileName[-1] = '\0';

	return lpResult;
}

BOOL CreateEmptyFileA
(
	_In_ LPSTR lpPath
)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BOOL Result = FALSE;

	hFile = CreateFileA(lpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateFileA", GetLastError());
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(INVALID_HANDLE_VALUE);
	}

	return Result;
}

BOOL CreateEmptyFileW
(
	_In_ LPWSTR lpPath
)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BOOL Result = FALSE;

	hFile = CreateFileW(lpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateFileW", GetLastError());
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	return Result;
}

BOOL SetFileOwner
(
	_In_ LPWSTR lpPath,
	_In_ LPSTR lpUserName
)
{
	BOOL Result = FALSE;
	BOOL IsDir = FALSE;
	DWORD dwLengthNeeded = 0;
	PSECURITY_DESCRIPTOR pSecurityDesc = NULL;
	PSID pNewSID = NULL;
	DWORD cbNewSID = 0;
	SID_NAME_USE NameUse;
	DWORD dwLastError = ERROR_SUCCESS;
	LPSTR lpReferencedDomainName = NULL;
	DWORD cchReferencedDomainName = 0;

	if (!IsPathExist(lpPath)) {
		goto CLEANUP;
	}

	GetFileSecurityW(lpPath, OWNER_SECURITY_INFORMATION, NULL, 0, &dwLengthNeeded);
	dwLastError = GetLastError();
	if (dwLastError != ERROR_INSUFFICIENT_BUFFER) {
		LOG_ERROR("GetFileSecurityW", dwLastError);
		goto CLEANUP;
	}

	pSecurityDesc = ALLOC(dwLengthNeeded);
	dwLastError = GetLastError();
	if (!GetFileSecurityW(lpPath, OWNER_SECURITY_INFORMATION, pSecurityDesc, dwLengthNeeded, &dwLengthNeeded)) {
		LOG_ERROR("GetFileSecurityW", dwLastError);
		goto CLEANUP;
	}

	if (!InitializeSecurityDescriptor(pSecurityDesc, SECURITY_DESCRIPTOR_REVISION)) {
		LOG_ERROR("InitializeSecurityDescriptor", GetLastError());
		goto CLEANUP;
	}

	SecureZeroMemory(&NameUse, sizeof(NameUse));
	LookupAccountNameA(NULL, lpUserName, pNewSID, &cbNewSID, lpReferencedDomainName, &cchReferencedDomainName, &NameUse);
	dwLastError = GetLastError();
	if (dwLastError != ERROR_INSUFFICIENT_BUFFER) {
		LOG_ERROR("LookupAccountNameA", dwLastError);
		goto CLEANUP;
	}
		
	pNewSID = ALLOC(cbNewSID);
	lpReferencedDomainName = ALLOC(cchReferencedDomainName);
	if (!LookupAccountNameA(NULL, lpUserName, pNewSID, &cbNewSID, lpReferencedDomainName, &cchReferencedDomainName, &NameUse)) {
		LOG_ERROR("LookupAccountNameA", GetLastError());
		goto CLEANUP;
	}

	if (!SetSecurityDescriptorOwner(pSecurityDesc, pNewSID, FALSE)) {
		LOG_ERROR("SetSecurityDescriptorOwner", GetLastError());
		goto CLEANUP;
	}

	if (!SetFileSecurityW(lpPath, OWNER_SECURITY_INFORMATION, pSecurityDesc)) {
		LOG_ERROR("SetFileSecurityA", GetLastError());
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	FREE(pSecurityDesc);
	FREE(pNewSID);
	FREE(lpReferencedDomainName);

	return Result;
}

LPWSTR CopyFileToFolder
(
	_In_ LPWSTR lpFilePath,
	_In_ LPWSTR lpDest
)
{
	LPWSTR lpFileName = NULL;
	DWORD dwError = ERROR_SUCCESS;
	LPWSTR lpNewFilePath = NULL;

	if (!IsFileExist(lpFilePath)) {
		goto CLEANUP;
	}

	lpFileName = PathFindFileNameW(lpFilePath);
	if (!IsFolderExist(lpDest)) {
		dwError = SHCreateDirectory(NULL, lpDest);
		if (dwError != ERROR_SUCCESS) {
			LOG_ERROR("SHCreateDirectory", dwError);
			goto CLEANUP;
		}
	}

	lpNewFilePath = DuplicateStrW(lpDest, lstrlenW(lpFileName) + 1);
	lstrcatW(lpNewFilePath, L"\\");
	lstrcatW(lpNewFilePath, lpFileName);
	if (!CopyFileW(lpFilePath, lpNewFilePath, FALSE)) {
		FREE(lpNewFilePath);
		lpNewFilePath = NULL;
		LOG_ERROR("CopyFileW", GetLastError());
		goto CLEANUP;
	}
CLEANUP:
	return lpNewFilePath;
}