#include "pch.h"

LPWSTR ConvertCharToWchar
(
	_In_ LPSTR lpInput
)
{
	DWORD dwInputLength = 0;
	DWORD dwOutputLength = 0;
	LPWSTR lpResult = NULL;

	dwInputLength = lstrlenA(lpInput);
	dwOutputLength = MultiByteToWideChar(CP_ACP, 0, lpInput, dwInputLength, NULL, 0);
	lpResult = ALLOC((dwOutputLength + 1) * sizeof(WCHAR));
	MultiByteToWideChar(CP_ACP, 0, lpInput, dwInputLength, lpResult, dwOutputLength);
	lpResult[dwOutputLength] = L'\0';
	return lpResult;
}

LPSTR ConvertWcharToChar
(
	_In_ LPWSTR lpInput
)
{
	DWORD dwInputLength = 0;
	DWORD dwOutputLength = 0;
	LPSTR lpResult = NULL;

	dwInputLength = lstrlenW(lpInput);
	dwOutputLength = WideCharToMultiByte(CP_UTF8, 0, lpInput, dwInputLength, NULL, 0, NULL, NULL);
	lpResult = ALLOC(dwOutputLength + 1);
	WideCharToMultiByte(CP_UTF8, 0, lpInput, dwInputLength, lpResult, dwOutputLength, NULL, NULL);
	lpResult[dwOutputLength] = '\0';
	return lpResult;
}

LPWSTR DuplicateStrW
(
	_In_ LPWSTR lpInput,
	_In_ DWORD dwLength
)
{
	LPWSTR lpResult = NULL;
	if (dwLength == 0)
	{
		lpResult = ALLOC((lstrlenW(lpInput) + 1) * sizeof(WCHAR));
		StrCpyW(lpResult, lpInput);
	}
	else {
		lpResult = ALLOC((dwLength + 1) * sizeof(WCHAR));
		memcpy(lpResult, lpInput, dwLength * sizeof(WCHAR));
	}
	return lpResult;
}

LPSTR DuplicateStrA
(
	_In_ LPSTR lpInput,
	_In_ DWORD dwLength
)
{
	LPSTR lpResult = NULL;
	if (dwLength == 0) {
		lpResult = ALLOC(lstrlenA(lpInput) + 1);
		StrCpyA(lpResult, lpInput);
	}
	else {
		lpResult = ALLOC(dwLength + 1);
		memcpy(lpResult, lpInput, dwLength);
	}
	
	return lpResult;
}

LPSTR SearchMatchStrA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpStartsWith,
	_In_ LPSTR lpEndsWith
)
{
	LPSTR lpTemp1, lpTemp2;
	DWORD dwLength = 0;

	lpTemp1 = StrStrA(lpInput, lpStartsWith);
	if (lpTemp1 == NULL) {
		return NULL;
	}

	lpTemp2 = StrStrA(lpTemp1, lpEndsWith);
	if (lpTemp2 == NULL) {
		return NULL;
	}

	dwLength = lpTemp2 - (lpTemp1 + lstrlenA(lpStartsWith));
	if (dwLength == 0) {
		return NULL;
	}

	return DuplicateStrA(&lpTemp1[lstrlenA(lpStartsWith)], dwLength);
}

LPSTR SearchMatchStrW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpStartsWith,
	_In_ LPWSTR lpEndsWith
)
{
	LPWSTR lpTemp1, lpTemp2;
	DWORD dwLength = 0;

	lpTemp1 = StrStrW(lpInput, lpStartsWith);
	if (lpTemp1 == NULL) {
		return NULL;
	}

	lpTemp2 = StrStrW(lpTemp1, lpEndsWith);
	if (lpTemp2 == NULL) {
		return NULL;
	}

	dwLength = (lpTemp2 - (&lpTemp1[lstrlenW(lpStartsWith)])) / sizeof(WCHAR);
	if (dwLength == 0) {
		return NULL;
	}

	return DuplicateStrW(&lpTemp1[lstrlenW(lpStartsWith)], dwLength);
}

LPSTR ConvertToHexString
(
	_In_ PBYTE pInput,
	_In_ DWORD cbInput
)
{
	LPSTR lpResult = NULL;
	DWORD i = 0;
	DWORD j = 0;

	lpResult = ALLOC((cbInput * 2) + 1);
	for (i = 0; i < cbInput; i++) {
		j += wsprintfA(&lpResult[j], "%02X", pInput[i]);
	}

	lpResult[j] = '\0';
	return lpResult;
}

PBYTE FromHexString
(
	_In_ LPSTR lpHexString
)
{
	DWORD dwLength = lstrlenA(lpHexString) / 2;
	PBYTE pResult = ALLOC(dwLength);

	for (DWORD i = 0; i < dwLength; i++) {
		sscanf_s(&lpHexString[i * 2], "%02x", &pResult[i]);
	}

	return pResult;
}

LPSTR Base64Encode
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer,
	_In_ BOOL IsStrict
)
{
	PBYTE pResult = NULL;
	DWORD cbResult = 0;

	if (!CryptBinaryToStringA(pBuffer, cbBuffer, CRYPT_STRING_BASE64, NULL, &cbResult)) {
		return NULL;
	}

	pResult = ALLOC(cbResult + 1);
	if (!CryptBinaryToStringA(pBuffer, cbBuffer, CRYPT_STRING_BASE64, pResult, &cbResult)) {
		return NULL;
	}

	pResult[lstrlenA(pResult) - 1] = '\0';
	pResult[lstrlenA(pResult) - 1] = '\0';
	if (IsStrict) {
		if (pResult[lstrlenA(pResult) - 1] == '=') {
			pResult[lstrlenA(pResult) - 1] = '\0';
		}

		if (pResult[lstrlenA(pResult) - 1] == '=') {
			pResult[lstrlenA(pResult) - 1] = '\0';
		}
	}

	return pResult;
}