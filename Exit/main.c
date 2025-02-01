#include <Windows.h>
#include <stdio.h>
#include <Shlwapi.h>

#define ALLOC(X) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, X)
#define FREE(X) HeapFree(GetProcessHeap(), 0, X)
#define REALLOC(X, Y) HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, X, Y)

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

LPWSTR DuplicateStrW
(
	_In_ LPWSTR lpInput,
	_In_ DWORD dwAdditionalLength
)
{
	LPWSTR lpResult = NULL;
	DWORD cbInput = 0;

	if (lpInput == NULL) {
		return ALLOC(sizeof(WCHAR));
	}

	cbInput = lstrlenW(lpInput);
	if (dwAdditionalLength == 0) {
		lpResult = ALLOC((cbInput + 1) * sizeof(WCHAR));
	}
	else {
		lpResult = ALLOC((cbInput + dwAdditionalLength + 1) * sizeof(WCHAR));
	}

	lstrcpyW(lpResult, lpInput);
	return lpResult;
}

VOID Override
(
	_In_ LPWSTR lpPath,
	_In_ LPWSTR lpDest
)
{
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW FindData;
	LPWSTR lpMask = NULL;
	LPWSTR lpNewPath = NULL;
	LPWSTR lpNewDest = NULL;

	SecureZeroMemory(&FindData, sizeof(FindData));
	lpMask = DuplicateStrW(lpPath, 2);
	lstrcatW(lpMask, L"\\*");
	hFind = FindFirstFileW(lpMask, &FindData);
	if (hFind == INVALID_HANDLE_VALUE) {
		goto CLEANUP;
	}

	do {
		if (!lstrcmpW(FindData.cFileName, L".") || !lstrcmpW(FindData.cFileName, L"..")) {
			continue;
		}

		lpNewPath = DuplicateStrW(lpPath, lstrlenW(FindData.cFileName) + 1);
		lstrcatW(lpNewPath, L"\\");
		lstrcatW(lpNewPath, FindData.cFileName);

		lpNewDest = DuplicateStrW(lpDest, lstrlenW(FindData.cFileName) + 1);
		lstrcatW(lpNewDest, L"\\");
		lstrcatW(lpNewDest, FindData.cFileName);
		if (IsFolderExist(lpNewPath)) {
			CreateDirectoryW(lpNewDest, NULL);
			Override(lpNewPath, lpNewDest);
			RemoveDirectoryW(lpNewPath);
		}
		else {
			MoveFileW(lpNewPath, lpNewDest);
		}

		FREE(lpNewPath);
		FREE(lpNewDest);
	} while (FindNextFileW(hFind, &FindData));

CLEANUP:
	if (hFind != INVALID_HANDLE_VALUE) {
		FindClose(hFind);
	}

	if (lpMask != NULL) {
		FREE(lpMask);
	}

	return;
}

int WinMain
(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nShowCmd
)
{
	LPWSTR lpInstallerPath = NULL;
	WCHAR wszCurrentPath[MAX_PATH];
	LPWSTR lpTemp = NULL;
	
	SecureZeroMemory(wszCurrentPath, sizeof(wszCurrentPath));
	GetModuleFileNameW(NULL, wszCurrentPath, _countof(wszCurrentPath));
	lpTemp = PathFindFileNameW(wszCurrentPath);
	lpTemp[0] = L'\0';
	lpInstallerPath = DuplicateStrW(wszCurrentPath, lstrlenW(L"\\Installer"));
	lstrcatW(lpInstallerPath, L"Installer");
	if (!IsFolderExist(lpInstallerPath)) {
		return -1;
	}

	Sleep(120);
	Override(lpInstallerPath, wszCurrentPath);
	RemoveDirectoryW(lpInstallerPath);
CLEANUP:
	FREE(lpInstallerPath);

	return 0;
}