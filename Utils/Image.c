#include "pch.h"

PBYTE LoadImageResource
(
	_In_ LPVOID lpImageBase,
	_In_ LPWSTR lpName,
	_In_ LPWSTR lpType,
	_Out_opt_ PDWORD pcbResource
)
{
	LDR_RESOURCE_INFO ResourceInfo;
	PIMAGE_RESOURCE_DATA_ENTRY pResourceData = NULL;
	PBYTE pResult = NULL;
	ULONG cbResult = 0;

	SecureZeroMemory(&ResourceInfo, sizeof(ResourceInfo));
	ResourceInfo.Type = lpType;
	ResourceInfo.Name = lpName;
	ResourceInfo.Language = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
	if (!NT_SUCCESS(LdrFindResource_U(lpImageBase, &ResourceInfo, RESOURCE_DATA_LEVEL, &pResourceData))) {
		LogError(L"LdrFindResource_U failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	if (!NT_SUCCESS(LdrAccessResource(lpImageBase, pResourceData, &pResult, &cbResult))) {
		pResult = NULL;
		LogError(L"LdrAccessResource failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	if (pcbResource != NULL) {
		*pcbResource = cbResult;
	}
CLEANUP:
	return pResult;
}

PBYTE LoadResourceCopy
(
	_In_ LPVOID lpImageBase,
	_In_ LPWSTR lpName,
	_In_ LPWSTR lpType,
	_Out_opt_ PDWORD pcbResource
)
{
	PBYTE pResourceData = NULL;
	PBYTE pResult = NULL;
	ULONG cbResult = NULL;

	pResourceData = LoadImageResource(lpImageBase, lpName, lpType, &cbResult);
	if (pResourceData == NULL) {
		return NULL;
	}

	pResult = ALLOC(cbResult + 1);
	memcpy(pResult, pResourceData, cbResult);
	if (pcbResource != NULL) {
		*pcbResource = cbResult;
	}

	return pResult;
}

PVOID GetFileVersionInfoValue
(
	_In_ PVS_VERSION_INFO_STRUCT32 pVersionInfo
)
{
	LPWSTR lpKeyOffset = pVersionInfo->Key + lstrlenW(pVersionInfo->Key) + 1;
	return PTR_ADD_OFFSET(pVersionInfo, ALIGN_UP(PTR_SUB_OFFSET(lpKeyOffset, pVersionInfo), ULONG));
}

BOOL GetFileVersionInfoKey
(
	_In_ PVS_VERSION_INFO_STRUCT32 pVersionInfo,
	_In_ SIZE_T KeyLength,
	_In_ PWSTR Key,
	_Out_opt_ PVOID* Buffer
)
{
	PVOID pValue = NULL;
	ULONG uValueOffset = 0;
	PVS_VERSION_INFO_STRUCT32 pChild = NULL;

	if (!(pValue = GetFileVersionInfoValue(pVersionInfo))) {
		return FALSE;
	}

	uValueOffset = pVersionInfo->ValueLength * (pVersionInfo->Type ? sizeof(WCHAR) : sizeof(BYTE));
	pChild = PTR_ADD_OFFSET(pValue, ALIGN_UP(uValueOffset, ULONG));
	while ((ULONG_PTR)pChild < (ULONG_PTR)PTR_ADD_OFFSET(pVersionInfo, pVersionInfo->Length)) {
		if (_wcsnicmp(pChild->Key, Key, KeyLength) == 0 && pChild->Key[KeyLength] == UNICODE_NULL) {
			if (Buffer) {
				*Buffer = pChild;
			}

			return TRUE;
		}

		if (pChild->Length == 0) {
			break;
		}

		pChild = PTR_ADD_OFFSET(pChild, ALIGN_UP(pChild->Length, ULONG));
	}

	return FALSE;
}

BOOL GetFileVersionVarFileInfoValue
(
	_In_ PVOID VersionInfo,
	_In_ LPWSTR lpKeyName,
	_Out_opt_ PVOID* pBuffer,
	_Out_opt_ PULONG pcbBuffer
)
{
	LPWSTR lpVarFileBlockName = L"VarFileInfo";
	PVS_VERSION_INFO_STRUCT32 pVarfileBlockInfo = NULL;
	PVS_VERSION_INFO_STRUCT32 pVarfileBlockValue;

	if (GetFileVersionInfoKey(VersionInfo, lstrlenW(lpVarFileBlockName), lpVarFileBlockName, &pVarfileBlockInfo)) {
		if (GetFileVersionInfoKey(pVarfileBlockInfo, lstrlenW(lpKeyName), lpKeyName, &pVarfileBlockValue)) {
			if (pcbBuffer) {
				*pcbBuffer = pVarfileBlockValue->ValueLength;
			}

			if (pBuffer) {
				*pBuffer = GetFileVersionInfoValue(pVarfileBlockValue);
			}

			return TRUE;
		}
	}

	return FALSE;
}

ULONG GetFileVersionInfoLangCodePage
(
	_In_ PVOID VersionInfo
)
{
	LPWSTR lpTranslationName = L"Translation";
	PLANGANDCODEPAGE pCodePage = NULL;
	ULONG cbCodePage = 0;

	if (GetFileVersionVarFileInfoValue(VersionInfo, lpTranslationName, &pCodePage, &cbCodePage)) {
		return ((ULONG)pCodePage[0].uLanguage << 16) + pCodePage[0].uCodePage;
	}

	return (MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US) << 16) + 1252;
}