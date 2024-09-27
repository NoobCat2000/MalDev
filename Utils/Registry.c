#include "pch.h"

BOOL AddRegKey
(
	_In_ HKEY hRootKey,
	_In_ LPWSTR lpSubKey,
	_In_ LPWSTR lpKeyName,
	_In_ LPVOID lpDefaultValue,
	_In_ DWORD cbDefaultValue
)
{
	LSTATUS Status = ERROR_SUCCESS;
	HKEY hKey = NULL;
	BOOL Result = FALSE;
	LPWSTR lpFullSubKey = NULL;
	DWORD cbFullSubKey = 0;

	cbFullSubKey = lstrlenW(lpSubKey) + lstrlenW(lpKeyName) + 1;
	lpFullSubKey = ALLOC((cbFullSubKey + 1) * sizeof(WCHAR));
	wsprintfW(lpFullSubKey, L"%s\\%s", lpSubKey, lpKeyName);
	Status = RegCreateKeyExW(hRootKey, lpFullSubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegCreateKeyExW", Status);
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	if (lpFullSubKey != NULL) {
		FREE(lpFullSubKey);
	}

	return Result;
}

BOOL QueryRegValue
(
	_In_ HKEY hRootKey,
	_In_ LPWSTR lpSubKey,
	_In_ LPWSTR lpValueName,
	_Out_ PBYTE* pOutput,
	_Out_ PDWORD pcbOutput
)
{
	HKEY hKey = NULL;
	BOOL Result = FALSE;
	LSTATUS Status = ERROR_SUCCESS;
	DWORD cbData = 0;
	PBYTE pData = NULL;

	Status = RegOpenKeyExW(hRootKey, lpSubKey, 0, KEY_READ, &hKey);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegOpenKeyExW", Status);
		goto CLEANUP;
	}

	Status = RegQueryValueExW(hKey, lpValueName, NULL, NULL, NULL, &cbData);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegQueryValueExW", Status);
		goto CLEANUP;
	}

	pData = ALLOC(cbData + 1);
	Status = RegQueryValueExW(hKey, lpValueName, NULL, NULL, pData, &cbData);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegQueryValueExW", Status);
		goto CLEANUP;
	}

	*pOutput = pData;
	if (pcbOutput != NULL) {
		*pcbOutput = cbData;
	}

	Result = TRUE;
CLEANUP:
	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	if (!Result && pData != NULL) {
		FREE(pData);
	}

	return Result;
}

//BOOL SetRegValue
//(
//	_In_ HKEY hRootKey,
//	_In_ LPWSTR lpSubKey,
//	_In_ LPWSTR lpValueName,
//	_In_ LPVOID lpValue,
//	_In_ DWORD cbValue
//)
//{
//	HKEY hKey = NULL;
//	BOOL Result = FALSE;
//	LSTATUS Status = ERROR_SUCCESS;
//	DWORD cbData = 0;
//	PBYTE pData = NULL;
//
//	Status = RegOpenKeyExW(hRootKey, lpSubKey, 0, KEY_READ | KEY_WRITE, &hKey);
//	if (Status != ERROR_SUCCESS) {
//		LogError(L"RegOpenKeyExW failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
//		goto CLEANUP;
//	}
//
//	Status = RegSetValueExW(hKey, lpValueName, 0, )
//
//	Result = TRUE;
//CLEANUP:
//	if (hKey != NULL) {
//		RegCloseKey(hKey);
//	}
//
//	return Result;
//}