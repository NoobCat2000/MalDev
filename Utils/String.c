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
	_In_ DWORD dwAdditionalLength
)
{
	LPWSTR lpResult = NULL;
	DWORD cbInput = lstrlenW(lpInput);

	if (dwAdditionalLength == 0)
	{
		lpResult = ALLOC((cbInput + 1) * sizeof(WCHAR));
	}
	else {
		lpResult = ALLOC((cbInput + dwAdditionalLength + 1) * sizeof(WCHAR));
	}

	lstrcpyW(lpResult, lpInput);
	return lpResult;
}

LPSTR DuplicateStrA
(
	_In_ LPSTR lpInput,
	_In_ DWORD dwAdditionalLength
)
{
	LPSTR lpResult = NULL;
	DWORD cbInput = lstrlenA(lpInput);

	if (dwAdditionalLength == 0) {
		lpResult = ALLOC(cbInput + 1);
	}
	else {
		lpResult = ALLOC(cbInput + 1 + dwAdditionalLength);
	}
	
	lstrcpyA(lpResult, lpInput);
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

PBYTE Base64Decode
(
	_In_ LPSTR lpInput,
	_Out_ PDWORD pcbOutput
)
{
	DWORD cbInput = lstrlenA(lpInput);
	DWORD cbOutput = 0;
	PBYTE pResult = NULL;

	if (!CryptStringToBinaryA(lpInput, cbInput, CRYPT_STRING_BASE64, NULL, &cbOutput, NULL, NULL)) {
		LogError(L"CryptStringToBinaryA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		return NULL;
	}

	pResult = ALLOC(cbOutput);
	if (!CryptStringToBinaryA(lpInput, cbInput, CRYPT_STRING_BASE64, pResult, &cbOutput, NULL, NULL)) {
		LogError(L"CryptStringToBinaryA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		FREE(pResult);
		return NULL;
	}

	if (pcbOutput != NULL) {
		*pcbOutput = cbOutput;
	}

	return pResult;
}

LPWSTR StrConcatenateW
(
	_In_ LPWSTR lpString1,
	_In_ LPWSTR lpString2
)
{
	LPWSTR lpResult = NULL;
	lpResult = ALLOC((lstrlenW(lpString1) + lstrlenW(lpString2) + 1) * sizeof(WCHAR));
	lstrcpyW(lpResult, lpString1);
	lstrcatW(lpResult, lpString2);

	return lpResult;
}

LPSTR StrConcatenateA
(
	_In_ LPSTR lpString1,
	_In_ LPSTR lpString2
)
{
	LPSTR lpResult = NULL;
	lpResult = ALLOC(lstrlenA(lpString1) + lstrlenA(lpString2) + 1);
	lstrcpyA(lpResult, lpString1);
	lstrcatA(lpResult, lpString2);

	return lpResult;
}

LPWSTR StrInsertW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpInsertedStr,
	_In_ DWORD dwPos
)
{
	LPWSTR lpResult = NULL;
	WCHAR chBackup = lpInput[dwPos];
	
	lpResult = ALLOC((lstrlenW(lpInput) + lstrlenW(lpInsertedStr) + 1) * sizeof(WCHAR));
	memcpy(lpResult, lpInput, dwPos * sizeof(WCHAR));
	lstrcatW(lpResult, lpInsertedStr);
	lstrcatW(lpResult, &lpInput[dwPos]);

	return lpResult;
}

LPSTR StrInsertA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpInsertedStr,
	_In_ DWORD dwPos
)
{
	LPSTR lpResult = NULL;
	CHAR chBackup = lpInput[dwPos];

	lpResult = ALLOC(lstrlenA(lpInput) + lstrlenA(lpInsertedStr) + 1);
	memcpy(lpResult, lpInput, dwPos);
	lstrcatA(lpResult, lpInsertedStr);
	lstrcatA(lpResult, &lpInput[dwPos]);

	return lpResult;
}

LPWSTR StrReplaceW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpMatchedStr,
	_In_ LPWSTR lpReplacedStr,
	_In_ BOOL IsReplaceAll,
	_In_ DWORD dwIdxOfOccurence
)
{
	PDWORD pMatchedPositions = NULL;
	DWORD cbInput = lstrlenW(lpInput);
	DWORD cbMatchedStr = lstrlenW(lpMatchedStr);
	DWORD cbReplacedStr = lstrlenW(lpReplacedStr);
	LPWSTR lpResult = NULL;
	DWORD i = 0;
	DWORD dwNumOfMatches = 0;
	LPWSTR lpTemp = NULL;
	DWORD cbResult = 0;
	WCHAR chTmp = L'\0';

	if (IsReplaceAll && dwIdxOfOccurence != 0) {
		goto CLEANUP;
	}

	pMatchedPositions = ALLOC(sizeof(DWORD) * (cbInput / cbMatchedStr));
	for (i = 0; i < cbInput / cbMatchedStr; i++) {
		pMatchedPositions[i] = -1;
		if (i == 0) {
			lpTemp = StrStrW(lpInput, lpMatchedStr);
			if (lpTemp == NULL) {
				break;
			}

			pMatchedPositions[i] = lpTemp - lpInput;
		}
		else {
			if (pMatchedPositions[i] + cbMatchedStr >= cbInput) {
				break;
			}

			lpTemp = StrStrW(lpInput + pMatchedPositions[i - 1] + cbMatchedStr, lpMatchedStr);
			if (lpTemp == NULL) {
				break;
			}

			pMatchedPositions[i] = lpTemp - lpInput;
		}

		if (pMatchedPositions[i] != -1) {
			dwNumOfMatches++;
			if (dwIdxOfOccurence > 0 && dwNumOfMatches == dwIdxOfOccurence) {
				lpResult = ALLOC((cbInput - cbMatchedStr + cbReplacedStr + 1) * sizeof(WCHAR));
				memcpy(lpResult, lpInput, pMatchedPositions[i] * sizeof(WCHAR));
				lstrcatW(lpResult, lpReplacedStr);
				lstrcatW(lpResult, lpInput + pMatchedPositions[i] + cbMatchedStr);
				goto CLEANUP;
			}
		}
	}

	if (dwNumOfMatches == 0 || dwIdxOfOccurence > dwNumOfMatches) {
		goto CLEANUP;
	}

	pMatchedPositions = REALLOC(pMatchedPositions, dwNumOfMatches * sizeof(DWORD));
	if (IsReplaceAll) {
		cbResult = cbInput + ((cbReplacedStr - cbMatchedStr) * dwNumOfMatches);
		lpResult = ALLOC((cbResult + 1) * sizeof(WCHAR));
		memcpy(lpResult, lpInput, pMatchedPositions[0] * sizeof(WCHAR));
		for (i = 0; i < dwNumOfMatches; i++) {
			lstrcatW(lpResult, lpReplacedStr);
			if (i < dwNumOfMatches - 1) {
				memcpy(lpResult + lstrlenW(lpResult), lpInput + pMatchedPositions[i] + cbMatchedStr, (pMatchedPositions[i + 1] - pMatchedPositions[i] - cbMatchedStr) * sizeof(WCHAR));
			}
			else {
				lstrcatW(lpResult, lpInput + pMatchedPositions[i] + cbMatchedStr);
			}
		}
	}

CLEANUP:
	if (pMatchedPositions != NULL) {
		FREE(pMatchedPositions);
	}

	return lpResult;
}

LPSTR StrReplaceA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpMatchedStr,
	_In_ LPSTR lpReplacedStr,
	_In_ BOOL IsReplaceAll,
	_In_ DWORD dwIdxOfOccurence
)
{
	PDWORD pMatchedPositions = NULL;
	DWORD cbInput = lstrlenA(lpInput);
	DWORD cbMatchedStr = lstrlenA(lpMatchedStr);
	DWORD cbReplacedStr = lstrlenA(lpReplacedStr);
	LPSTR lpResult = NULL;
	DWORD i = 0;
	DWORD dwNumOfMatches = 0;
	LPSTR lpTemp = NULL;
	DWORD cbResult = 0;
	CHAR chTmp = '\0';

	if (IsReplaceAll && dwIdxOfOccurence != 0) {
		goto CLEANUP;
	}

	pMatchedPositions = ALLOC(sizeof(DWORD) * (cbInput / cbMatchedStr));
	for (i = 0; i < cbInput / cbMatchedStr; i++) {
		pMatchedPositions[i] = -1;
		if (i == 0) {
			lpTemp = StrStrA(lpInput, lpMatchedStr);
			if (lpTemp == NULL) {
				break;
			}

			pMatchedPositions[i] = lpTemp - lpInput;
		}
		else {
			if (pMatchedPositions[i] + cbMatchedStr >= cbInput) {
				break;
			}

			lpTemp = StrStrA(lpInput + pMatchedPositions[i - 1] + cbMatchedStr, lpMatchedStr);
			if (lpTemp == NULL) {
				break;
			}

			pMatchedPositions[i] = lpTemp - lpInput;
		}

		if (pMatchedPositions[i] != -1) {
			dwNumOfMatches++;
			if (dwIdxOfOccurence > 0 && dwNumOfMatches == dwIdxOfOccurence) {
				lpResult = ALLOC(cbInput - cbMatchedStr + cbReplacedStr + 1);
				memcpy(lpResult, lpInput, pMatchedPositions[i]);
				lstrcatA(lpResult, lpReplacedStr);
				lstrcatA(lpResult, lpInput + pMatchedPositions[i] + cbMatchedStr);
				goto CLEANUP;
			}
		}
	}

	if (dwNumOfMatches == 0 || dwIdxOfOccurence > dwNumOfMatches) {
		goto CLEANUP;
	}

	pMatchedPositions = REALLOC(pMatchedPositions, dwNumOfMatches * sizeof(DWORD));
	if (IsReplaceAll) {
		cbResult = cbInput + ((cbReplacedStr - cbMatchedStr) * dwNumOfMatches);
		lpResult = ALLOC(cbResult + 1);
		memcpy(lpResult, lpInput, pMatchedPositions[0]);
		for (i = 0; i < dwNumOfMatches; i++) {
			lstrcatA(lpResult, lpReplacedStr);
			if (i < dwNumOfMatches - 1) {
				memcpy(lpResult + lstrlenA(lpResult), lpInput + pMatchedPositions[i] + cbMatchedStr, pMatchedPositions[i + 1] - pMatchedPositions[i] - cbMatchedStr);
			}
			else {
				lstrcatA(lpResult, lpInput + pMatchedPositions[i] + cbMatchedStr);
			}
		}
	}

CLEANUP:
	if (pMatchedPositions != NULL) {
		FREE(pMatchedPositions);
	}

	return lpResult;
}

LPSTR GenGUIDStrA() {
	GUID Guid;
	LPSTR lpResult = NULL;
	LPOLESTR lpOutput = ALLOC(40 * sizeof(WCHAR));
	DWORD cbResult = 0;

	RtlSecureZeroMemory(&Guid, sizeof(Guid));
	if (CoCreateGuid(&Guid) != S_OK) {
		goto CLEANUP;
	}

	cbResult = StringFromGUID2(&Guid, lpOutput, 40);
	if (cbResult == 0) {
		goto CLEANUP;
	}

	lpResult = ConvertWcharToChar(lpOutput);
CLEANUP:
	if (lpOutput != NULL) {
		FREE(lpOutput);
	}

	return lpResult;
}

LPWSTR GenGUIDStrW() {
	GUID Guid;
	LPWSTR lpResult = NULL;
	LPOLESTR lpOutput = ALLOC(40);
	DWORD cbResult = 0;

	RtlSecureZeroMemory(&Guid, sizeof(Guid));
	if (CoCreateGuid(&Guid) != S_OK) {
		goto CLEANUP;
	}

	cbResult = StringFromGUID2(&Guid, lpOutput, 40);
	if (cbResult == 0) {
		goto CLEANUP;
	}

	lpResult = DuplicateStrW(lpOutput, 0);
CLEANUP:
	if (lpOutput != NULL) {
		FREE(lpOutput);
	}

	return lpResult;
}

BOOL IsStrStartsWithA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpMatchedStr
)
{
	DWORD cbInput = lstrlenA(lpInput);
	DWORD cbMatchedStr = lstrlenA(lpMatchedStr);
	if (cbMatchedStr > cbInput) {
		return FALSE;
	}

	if (!memcmp(lpInput, lpMatchedStr, cbMatchedStr)) {
		return TRUE;
	}

	return FALSE;
}

BOOL IsStrStartsWithW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpMatchedStr
)
{
	DWORD cbInput = lstrlenW(lpInput);
	DWORD cbMatchedStr = lstrlenW(lpMatchedStr);
	if (cbMatchedStr > cbInput) {
		return FALSE;
	}

	if (!memcmp(lpInput, lpMatchedStr, cbMatchedStr * sizeof(WCHAR))) {
		return TRUE;
	}

	return FALSE;
}

BOOL IsStrEndsWithW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpMatchedStr
)
{
	DWORD cbInput = lstrlenW(lpInput);
	DWORD cbMatchedStr = lstrlenW(lpMatchedStr);
	LPWSTR lpPos = NULL;

	if (cbMatchedStr > cbInput) {
		return FALSE;
	}

	lpPos = StrStrW(lpInput, lpMatchedStr);
	if (lpPos == NULL) {
		return FALSE;
	}

	if (lstrlenW(lpPos) != cbMatchedStr) {
		return FALSE;
	}

	return TRUE;
}

BOOL IsStrEndsWithA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpMatchedStr
)
{
	DWORD cbInput = lstrlenA(lpInput);
	DWORD cbMatchedStr = lstrlenA(lpMatchedStr);
	LPSTR lpPos = NULL;

	if (cbMatchedStr > cbInput) {
		return FALSE;
	}

	lpPos = StrStrA(lpInput, lpMatchedStr);
	if (lpPos == NULL) {
		return FALSE;
	}

	if (lstrlenA(lpPos) != cbMatchedStr) {
		return FALSE;
	}

	return TRUE;
}

VOID TrimSuffixW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpSuffix
)
{
	LPWSTR lpPos = NULL;

	if (!IsStrEndsWithW(lpInput, lpSuffix)) {
		return NULL;
	}

	lpPos = StrStrW(lpInput, lpSuffix);
	if (lpPos == NULL) {
		return lpInput;
	}

	RtlSecureZeroMemory(lpPos, lstrlenW(lpSuffix) * sizeof(WCHAR));
}

VOID TrimSuffixA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpSuffix
)
{
	LPSTR lpPos = NULL;

	if (!IsStrEndsWithA(lpInput, lpSuffix)) {
		return NULL;
	}

	lpPos = StrStrA(lpInput, lpSuffix);
	if (lpPos == NULL) {
		return lpInput;
	}

	RtlSecureZeroMemory(lpPos, lstrlenA(lpSuffix));
}

LPSTR StrInsertCharA
(
	_In_ LPSTR lpInput,
	_In_ CHAR CharValue,
	_In_ DWORD dwPos
)
{
	DWORD cbInput = lstrlenA(lpInput);
	LPSTR lpResult = ALLOC(cbInput + 2);

	memcpy(lpResult, lpInput, dwPos);
	lpResult[dwPos] = CharValue;
	lstrcatA(lpResult, lpInput + dwPos);

	return lpResult;
}

LPWSTR StrInsertCharW
(
	_In_ LPWSTR lpInput,
	_In_ WCHAR CharValue,
	_In_ DWORD dwPos
)
{
	DWORD cbInput = lstrlenW(lpInput);
	LPWSTR lpResult = ALLOC((cbInput + 2) * sizeof(WCHAR));

	memcpy(lpResult, lpInput, dwPos * sizeof(WCHAR));
	lpResult[dwPos] = CharValue;
	lstrcatW(lpResult, &lpInput[dwPos]);

	return lpResult;
}