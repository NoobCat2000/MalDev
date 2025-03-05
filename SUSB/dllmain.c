#include "pch.h"

THREATSCANNER_INITIALIZEEX fnThreatScanner_InitializeEx;
THREATSCANNER_CREATEINSTANCE fnThreatScanner_CreateInstance;
THREATSCANNER_SETINTOPTION fnThreatScanner_SetIntOption;
THREATSCANNER_SETSTRINGOPTION fnThreatScanner_SetStringOption;
THREATSCANNER_SETSCANCALLBACK2 fnThreatScanner_SetScanCallback2;
THREATSCANNER_SETENGINESUNLOADCALLBACK fnThreatScanner_SetEnginesUnloadCallback;
THREATSCANNER_SCANPATH fnThreatScanner_ScanPath;
THREATSCANNER_SCANOBJECT fnThreatScanner_ScanObject;
THREATSCANNER_SCANOBJECTBYHANDLE fnThreatScanner_ScanObjectByHandle;
THREATSCANNER_INITIALIZEMEMORYSCAN fnThreatScanner_InitializeMemoryScan;
THREATSCANNER_UNINITIALIZEMEMORYSCAN fnThreatScanner_UninitializeMemoryScan;
THREATSCANNER_SCANMEMORYEX fnThreatScanner_ScanMemoryEx;
THREATSCANNER_SETPASSWORDCALLBACK fnThreatScanner_SetPasswordCallback;
THREATSCANNER_SETEXTCALLBACK fnThreatScanner_SetExtCallback;
THREATSCANNER_GETOPTION fnThreatScanner_GetOption;
THREATSCANNER_GETSCANSTATISTICS fnThreatScanner_GetScanStatistics;
THREATSCANNER_DESTROYINSTANCE fnThreatScanner_DestroyInstance;
THREATSCANNER_UNINITIALIZE fnThreatScanner_Uninitialize;
CThreatScanner* Scanner;

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

LPWSTR ConvertCharToWchar
(
	_In_ LPSTR lpInput
)
{
	DWORD dwInputLength = 0;
	DWORD dwOutputLength = 0;
	LPWSTR lpResult = NULL;

	dwInputLength = lstrlenA(lpInput);
	dwOutputLength = MultiByteToWideChar(CP_UTF8, 0, lpInput, dwInputLength, NULL, 0);
	lpResult = ALLOC((dwOutputLength + 1) * sizeof(WCHAR));
	MultiByteToWideChar(CP_UTF8, 0, lpInput, dwInputLength, lpResult, dwOutputLength);
	lpResult[dwOutputLength] = L'\0';
	return lpResult;
}

LPWSTR GetLicense
(
	_In_ LPWSTR lpPath
)
{
	PBYTE pLicense = NULL;
	DWORD cbLicense = 0;
	DWORD i = 0;
	DWORD j = 0;
	CHAR Key[] = "C:\\Windows\\debug";
	LPWSTR lpResult = NULL;

	pLicense = ReadFromFile(lpPath, &cbLicense);
	if (pLicense == NULL) {
		goto CLEANUP;
	}

	if (cbLicense < LICENSE_SIZE) {
		goto CLEANUP;
	}

	for (i = 0; i < LICENSE_SIZE; i++) {
		pLicense[i] ^= Key[i % lstrlenA(Key)];
	}

	lpResult = ConvertCharToWchar(pLicense);
CLEANUP:
	if (pLicense != NULL) {
		FREE(pLicense);
	}

	return lpResult;
}

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

__declspec(dllexport) INT NextAVInit
(
	_In_ LPWSTR lpNextAVPath
)
{
	LPWSTR lpScanDll = NULL;
	HMODULE hScanDll = NULL;
	INT RetCode = -1;
	INT Status = SCANAPI_SUCCESS;
	LPSTR lpLicensePath = NULL;
	LPWSTR lpLicense = NULL;
	LPSTR lpEnginePath = NULL;
	InitializeParams Param;

	lpScanDll = DuplicateStrW(lpNextAVPath, lstrlenW(L"\\scan.dll"));
	lstrcatW(lpScanDll, L"\\scan.dll");
	if (!IsFileExist(lpScanDll)) {
		goto CLEANUP;
	}

	hScanDll = LoadLibraryW(lpScanDll);
	if (hScanDll == NULL) {
		goto CLEANUP;
	}

	fnThreatScanner_InitializeEx = (THREATSCANNER_INITIALIZEEX)GetProcAddress(hScanDll, "ThreatScanner_InitializeEx");
	fnThreatScanner_CreateInstance = (THREATSCANNER_CREATEINSTANCE)GetProcAddress(hScanDll, "ThreatScanner_CreateInstance");
	fnThreatScanner_SetIntOption = (THREATSCANNER_SETINTOPTION)GetProcAddress(hScanDll, "ThreatScanner_SetIntOption");
	fnThreatScanner_SetStringOption = (THREATSCANNER_SETSTRINGOPTION)GetProcAddress(hScanDll, "ThreatScanner_SetStringOption");
	fnThreatScanner_SetScanCallback2 = (THREATSCANNER_SETSCANCALLBACK2)GetProcAddress(hScanDll, "ThreatScanner_SetScanCallback2");
	fnThreatScanner_SetEnginesUnloadCallback = (THREATSCANNER_SETENGINESUNLOADCALLBACK)GetProcAddress(hScanDll, "ThreatScanner_SetEnginesUnloadCallback");
	fnThreatScanner_ScanPath = (THREATSCANNER_SCANPATH)GetProcAddress(hScanDll, "ThreatScanner_ScanPath");
	fnThreatScanner_ScanObject = (THREATSCANNER_SCANOBJECT)GetProcAddress(hScanDll, "ThreatScanner_ScanObject");
	fnThreatScanner_ScanObjectByHandle = (THREATSCANNER_SCANOBJECTBYHANDLE)GetProcAddress(hScanDll, "ThreatScanner_ScanObjectByHandle");
	fnThreatScanner_InitializeMemoryScan = (THREATSCANNER_INITIALIZEMEMORYSCAN)GetProcAddress(hScanDll, "ThreatScanner_InitializeMemoryScan");
	fnThreatScanner_UninitializeMemoryScan = (THREATSCANNER_UNINITIALIZEMEMORYSCAN)GetProcAddress(hScanDll, "ThreatScanner_UninitializeMemoryScan");
	fnThreatScanner_ScanMemoryEx = (THREATSCANNER_SCANMEMORYEX)GetProcAddress(hScanDll, "ThreatScanner_ScanMemoryEx");
	fnThreatScanner_SetPasswordCallback = (THREATSCANNER_SETPASSWORDCALLBACK)GetProcAddress(hScanDll, "ThreatScanner_SetPasswordCallback");
	fnThreatScanner_SetExtCallback = (THREATSCANNER_SETEXTCALLBACK)GetProcAddress(hScanDll, "ThreatScanner_SetExtCallback");
	fnThreatScanner_GetOption = (THREATSCANNER_GETOPTION)GetProcAddress(hScanDll, "ThreatScanner_GetOption");
	fnThreatScanner_GetScanStatistics = (THREATSCANNER_GETSCANSTATISTICS)GetProcAddress(hScanDll, "ThreatScanner_GetScanStatistics");
	fnThreatScanner_DestroyInstance = (THREATSCANNER_DESTROYINSTANCE)GetProcAddress(hScanDll, "ThreatScanner_DestroyInstance");
	fnThreatScanner_Uninitialize = (THREATSCANNER_UNINITIALIZE)GetProcAddress(hScanDll, "ThreatScanner_Uninitialize");

	lpLicensePath = DuplicateStrW(lpNextAVPath, lstrlenW(L"\\license.txt"));
	lstrcatW(lpLicensePath, L"\\license.txt");
	lpLicense = GetLicense(lpLicensePath);
	if (lpLicense == NULL) {
		goto CLEANUP;
	}

	lpEnginePath = DuplicateStrW(lpNextAVPath, lstrlenW(L"\\db"));
	lstrcatW(lpEnginePath, L"\\db");
	if (!IsFolderExist(lpEnginePath)) {
		goto CLEANUP;
	}

	SecureZeroMemory(&Param, sizeof(Param));
	Param.nStructSize = sizeof(Param);
	Status = fnThreatScanner_InitializeEx(lpEnginePath, lpLicense, NULL, &Param);
	if (Status != SCANAPI_SUCCESS) {
		goto CLEANUP;
	}

	Status = fnThreatScanner_CreateInstance(&Scanner);
	if (Status != SCANAPI_SUCCESS) {
		goto CLEANUP;
	}

	Status = fnThreatScanner_SetIntOption(Scanner, _optScanArchives, 1);
	if (Status != SCANAPI_SUCCESS) {
		goto CLEANUP;
	}

	Status = fnThreatScanner_SetIntOption(Scanner, _optScanPacked, 1);
	if (Status != SCANAPI_SUCCESS) {
		goto CLEANUP;
	}

	Status = fnThreatScanner_SetIntOption(Scanner, _optDeepScan, 1);
	if (Status != SCANAPI_SUCCESS) {
		goto CLEANUP;
	}

	Status = fnThreatScanner_SetIntOption(Scanner, _optMaxArchiveFileSize, 100 * 1024 * 1024);
	if (Status != SCANAPI_SUCCESS) {
		goto CLEANUP;
	}

	RetCode = 0;
CLEANUP:
	if (lpLicense != NULL) {
		FREE(lpLicense);
	}

	if (lpScanDll != NULL) {
		FREE(lpScanDll);
	}

	if (lpLicensePath != NULL) {
		FREE(lpLicensePath);
	}

	if (lpEnginePath != NULL) {
		FREE(lpEnginePath);
	}

	return RetCode;
}

__declspec(dllexport) BOOL ScanFile
(
	_In_ LPWSTR lpFilePath,
	_In_ LPWSTR* NameOfMalware
)
{
	INT ScanStatus = 0;
	INT ThreatType = 0;
	INT Status = SCANAPI_SUCCESS;

	if (Scanner == NULL) {
		return FALSE;
	}

	fnThreatScanner_ScanObject(Scanner, OBJECT_TYPE_FILE, lpFilePath, FALSE, &ScanStatus, &ThreatType, NameOfMalware, 0, lpFilePath);
	if (Status != SCANAPI_SUCCESS) {
		return FALSE;
	}

	if (ScanStatus == OBJECT_STATUS_INFECTED) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

BOOL WINAPI DllMain
(
	HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpvReserved
)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		Scanner = NULL;
		break;
	case DLL_PROCESS_DETACH:
		if (lpvReserved != NULL) {
			break;
		}

		if (Scanner != NULL) {
			fnThreatScanner_DestroyInstance(Scanner);
			fnThreatScanner_Uninitialize();
		}

		break;
	}
	return TRUE;
}