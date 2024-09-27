#include "pch.h"

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
	_In_ LPWSTR lpKey,
	_In_ DWORD cchKey,
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
		if (_wcsnicmp(pChild->Key, lpKey, cchKey) == 0 && pChild->Key[cchKey] == UNICODE_NULL) {
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

	if (GetFileVersionInfoKey(VersionInfo, lpVarFileBlockName, lstrlenW(lpVarFileBlockName), &pVarfileBlockInfo)) {
		if (GetFileVersionInfoKey(pVarfileBlockInfo, lpKeyName, lstrlenW(lpKeyName), &pVarfileBlockValue)) {
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

LPSTR GetFileVersionInfoString2
(
	_In_ PVOID pVersionInfo,
	_In_ ULONG uLangCodePage,
	_In_ LPWSTR lpKeyName
)
{
	LPWSTR lpBlockInfoName = L"StringFileInfo";
	PVS_VERSION_INFO_STRUCT32 pBlockStringInfo = NULL;
	PVS_VERSION_INFO_STRUCT32 pBlockLangInfo = NULL;
	PVS_VERSION_INFO_STRUCT32 pStringNameBlockInfo;
	LPWSTR lpStringNameBlockValue = NULL;
	DWORD dwReturnedLength = 0;
	WCHAR wszLangNameString[65];
	DWORD i = 0;

	if (!GetFileVersionInfoKey(pVersionInfo, lpBlockInfoName, lstrlenW(lpBlockInfoName), &pBlockStringInfo)) {
		return NULL;
	}

	SecureZeroMemory(wszLangNameString, sizeof(wszLangNameString));
	for (i = 0; i < 8; i++) {
		wsprintfW(&wszLangNameString[lstrlenW(wszLangNameString)], L"%x", (uLangCodePage >> (28 - (i * 4))) & 0xF);
	}

	if (!GetFileVersionInfoKey(pBlockStringInfo, wszLangNameString, lstrlenW(wszLangNameString), &pBlockLangInfo)) {
		return NULL;
	}

	if (!GetFileVersionInfoKey(pBlockLangInfo, lpKeyName, lstrlenW(lpKeyName), &pStringNameBlockInfo)) {
		return NULL;
	}

	if (pStringNameBlockInfo->ValueLength <= sizeof(UNICODE_NULL)) {
		return NULL;
	}

	if (!(lpStringNameBlockValue = GetFileVersionInfoValue(pStringNameBlockInfo))) {
		return NULL;
	}

	return ConvertWcharToChar(lpStringNameBlockValue);
}

LPSTR GetFileVersionInfoStringEx
(
	_In_ PVOID VersionInfo,
	_In_ ULONG LangCodePage,
	_In_ LPWSTR lpKeyName
)
{
	LPSTR lpResult = NULL;

	if (lpResult = GetFileVersionInfoString2(VersionInfo, LangCodePage, lpKeyName)) {
		return lpResult;
	}

	if (lpResult = GetFileVersionInfoString2(VersionInfo, (LangCodePage & 0xffff0000) + 1252, lpKeyName)) {
		return lpResult;
	}

	if (lpResult = GetFileVersionInfoString2(VersionInfo, (MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US) << 16) + 1252, lpKeyName)) {
		return lpResult;
	}

	if (lpResult = GetFileVersionInfoString2(VersionInfo, (MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US) << 16) + 0, lpKeyName)) {
		return lpResult;
	}

	return NULL;
}

DWORD GetImageArchitecture
(
	_In_ LPSTR lpFilePath
)
{
	LPWSTR lpTempPath = NULL;
	DWORD cbBuffer = 0;
	PBYTE pBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHdr = NULL;
	PIMAGE_NT_HEADERS pNtHdr = NULL;
	DWORD dwResult = 0;

	lpTempPath = ConvertCharToWchar(lpFilePath);
	pBuffer = ReadFromFile(lpTempPath, &cbBuffer);
	if (pBuffer == NULL) {
		goto CLEANUP;
	}

	if (cbBuffer < 0x400) {
		goto CLEANUP;
	}

	pDosHdr = (PIMAGE_DOS_HEADER)pBuffer;
	pNtHdr = (PIMAGE_NT_HEADERS)(pBuffer + pDosHdr->e_lfanew);
	dwResult = pNtHdr->FileHeader.Machine;
CLEANUP:
	if (lpTempPath != NULL) {
		FREE(lpTempPath);
	}

	if (pBuffer != NULL) {
		FREE(pBuffer);
	}

	return dwResult;
}

PIMAGE_VERION GetImageVersion
(
	_In_ LPSTR lpFilePath
)
{
	DWORD cbVersionInfo = 0;
	DWORD dwHandle = 0;
	PBYTE pVersionInfo = NULL;
	VS_FIXEDFILEINFO* FixedFileInfo = NULL;
	DWORD i = 0;
	ULONG uLangCodePage = 0;
	PIMAGE_VERION pResult = NULL;
	DWORD dwLastError = NO_ERROR;

	cbVersionInfo = GetFileVersionInfoSizeA(lpFilePath, &dwHandle);
	pVersionInfo = ALLOC(cbVersionInfo);
	while (TRUE) {
		if (!GetFileVersionInfoA(lpFilePath, 0, cbVersionInfo, pVersionInfo)) {
			dwLastError = GetLastError();
			if (dwLastError == ERROR_INSUFFICIENT_BUFFER) {
				cbVersionInfo *= 2;
				pVersionInfo = REALLOC(pVersionInfo, cbVersionInfo);
			}
			else {
				LOG_ERROR("GetFileVersionInfoA", dwLastError);
				goto CLEANUP;
			}
		}

		break;
	}
	
	for (i = 0; i < cbVersionInfo; i += sizeof(DWORD)) {
		if (*(PDWORD)(pVersionInfo + i) == VS_FFI_SIGNATURE) {
			FixedFileInfo = (VS_FIXEDFILEINFO*)(pVersionInfo + i);
		}
	}

	if (FixedFileInfo == NULL) {
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(IMAGE_VERION));
	pResult->lpVersion = ALLOC(0x40);
	wsprintfA(pResult->lpVersion, "%d.%d.%d.%d", HIWORD(FixedFileInfo->dwFileVersionMS), LOWORD(FixedFileInfo->dwFileVersionMS), HIWORD(FixedFileInfo->dwFileVersionLS), LOWORD(FixedFileInfo->dwFileVersionLS));
	uLangCodePage = GetFileVersionInfoLangCodePage(pVersionInfo);
	pResult->lpCompanyName = GetFileVersionInfoStringEx(pVersionInfo, uLangCodePage, L"CompanyName");
	pResult->lpImageDesc = GetFileVersionInfoStringEx(pVersionInfo, uLangCodePage, L"FileDescription");
	pResult->lpProductName = GetFileVersionInfoStringEx(pVersionInfo, uLangCodePage, L"ProductName");
CLEANUP:
	if (pVersionInfo != NULL) {
		FREE(pVersionInfo);
	}

	return pResult;
}

VOID FreeImageVersion
(
	_In_ PIMAGE_VERION pImageVersion
)
{
	if (pImageVersion != NULL) {
		if (pImageVersion->lpVersion != NULL) {
			FREE(pImageVersion->lpVersion);
		}

		if (pImageVersion->lpCompanyName != NULL) {
			FREE(pImageVersion->lpCompanyName);
		}

		if (pImageVersion->lpImageDesc != NULL) {
			FREE(pImageVersion->lpImageDesc);
		}

		if (pImageVersion->lpProductName != NULL) {
			FREE(pImageVersion->lpProductName);
		}

		FREE(pImageVersion);
	}
}