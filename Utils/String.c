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