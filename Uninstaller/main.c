#include <Windows.h>
#include <Shlwapi.h>

#define ALLOC(X) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, X)
#define FREE(X) HeapFree(GetProcessHeap(), 0, X)
#define REALLOC(X, Y) HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, X, Y)

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
	if (dwAdditionalLength == 0)
	{
		lpResult = ALLOC((cbInput + 1) * sizeof(WCHAR));
	}
	else {
		lpResult = ALLOC((cbInput + dwAdditionalLength + 1) * sizeof(WCHAR));
	}

	lstrcpyW(lpResult, lpInput);
	return lpResult;
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
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	FREE(ShFileStruct.pFrom);
	return Result;
}

LPWSTR StrCatExW
(
	_In_ LPWSTR lpStr1,
	_In_ LPWSTR lpStr2
)
{
	DWORD cchResult = lstrlenW(lpStr1) + lstrlenW(lpStr2);

	if (lpStr1 == NULL) {
		lpStr1 = ALLOC((cchResult + 1) * sizeof(WCHAR));
	}
	else {
		lpStr1 = REALLOC(lpStr1, (cchResult + 1) * sizeof(WCHAR));
	}

	lstrcatW(lpStr1, lpStr2);
	lpStr1[cchResult] = L'\0';
	return lpStr1;
}

int WinMain
(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nShowCmd
)
{
	WCHAR wszCurrentDirectory[MAX_PATH];
	LPWSTR lpFileName = NULL;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA FindData;
	LPWSTR lpNewPath = NULL;
	LPWSTR lpMask = NULL;

	SecureZeroMemory(&FindData, sizeof(FindData));
	GetModuleFileNameW(NULL, wszCurrentDirectory, _countof(wszCurrentDirectory));
	lpFileName = PathFindFileNameW(wszCurrentDirectory);
	lpFileName[-1] = L'\0';
	lpMask = DuplicateStrW(wszCurrentDirectory, 0);
	lpMask = StrCatExW(lpMask, L"\\*");

	hFind = FindFirstFileW(lpMask, &FindData);
	if (hFind == INVALID_HANDLE_VALUE) {
		goto CLEANUP;
	}

	do {
		if (!lstrcmpW(FindData.cFileName, L".") || !lstrcmpW(FindData.cFileName, L"..") || !lstrcmpW(FindData.cFileName, lpFileName)) {
			continue;
		}

		lpNewPath = DuplicateStrW(wszCurrentDirectory, 0);
		lpNewPath = StrCatExW(lpNewPath, L"\\");
		lpNewPath = StrCatExW(lpNewPath, FindData.cFileName);
		DeletePath(lpNewPath);
		FREE(lpNewPath);
	} while (FindNextFileW(hFind, &FindData));

CLEANUP:
	FREE(lpMask);
	if (hFind != INVALID_HANDLE_VALUE) {
		FindClose(hFind);
	}

	return 0;
}