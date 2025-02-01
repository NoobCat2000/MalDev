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
	dwOutputLength = MultiByteToWideChar(CP_UTF8, 0, lpInput, dwInputLength, NULL, 0);
	lpResult = ALLOC((dwOutputLength + 1) * sizeof(WCHAR));
	MultiByteToWideChar(CP_UTF8, 0, lpInput, dwInputLength, lpResult, dwOutputLength);
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

LPWSTR StrAppendW
(
	_In_ LPWSTR lpStr1,
	_In_ LPWSTR lpStr2
)
{
	LPWSTR lpResult = NULL;

	lpResult = DuplicateStrW(lpStr1, lstrlenW(lpStr2));
	lstrcatW(lpResult, lpStr2);

	return lpResult;
}

LPSTR StrAppendA
(
	_In_ LPSTR lpStr1,
	_In_ LPSTR lpStr2
)
{
	LPSTR lpResult = NULL;

	lpResult = DuplicateStrA(lpStr1, lstrlenA(lpStr2));
	lstrcatA(lpResult, lpStr2);

	return lpResult;
}

LPWSTR DuplicateStrW
(
	_In_ LPWSTR lpInput,
	_In_ DWORD dwAdditionalLength
)
{
	LPWSTR lpResult = NULL;
	DWORD cbInput = 0;

	if (lpInput == NULL) {
		return ALLOC(sizeof(WCHAR));
	}

	cbInput = lstrlenW(lpInput);
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
	DWORD cbInput = 0;

	if (lpInput == NULL) {
		return ALLOC(sizeof(CHAR));
	}

	cbInput = lstrlenA(lpInput);
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

	return ExtractSubStrA(&lpTemp1[lstrlenA(lpStartsWith)], dwLength);
}

LPWSTR SearchMatchStrW
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

	dwLength = (((UINT64)lpTemp2 - (UINT64)lpTemp1) / sizeof(WCHAR)) - lstrlenW(lpStartsWith);
	if (dwLength == 0) {
		return NULL;
	}

	return ExtractSubStrW(&lpTemp1[lstrlenW(lpStartsWith)], dwLength);
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
	/*DWORD dwLength = lstrlenA(lpHexString) / 2;
	PBYTE pResult = ALLOC(dwLength);

	for (DWORD i = 0; i < dwLength; i++) {
		sscanf_s(&lpHexString[i * 2], "%02x", &pResult[i]);
	}

	return pResult;*/
}

LPSTR Base64Encode
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer,
	_In_ BOOL IsStrict
)
{
	LPSTR pResult = NULL;
	CHAR Base64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	DWORD dwEncodedSize = 0;
	DWORD i = 0;
	DWORD j = 0;
	UINT64 v = 0;

	dwEncodedSize = cbBuffer;
	if (cbBuffer % 3 != 0) {
		dwEncodedSize += 3 - (cbBuffer % 3);
	}

	dwEncodedSize /= 3;
	dwEncodedSize *= 4;
	pResult = ALLOC(dwEncodedSize + 1);
	for (i = 0, j = 0; i < cbBuffer; i += 3, j += 4) {
		v = pBuffer[i];
		if (i + 1 < cbBuffer) {
			v = v << 8 | pBuffer[i + 1];
		}
		else {
			v = v << 8;
		}

		if (i + 2 < cbBuffer) {
			v = v << 8 | pBuffer[i + 2];
		}
		else {
			v = v << 8;
		}

		/*v = i + 1 < cbBuffer ? v << 8 | pBuffer[i + 1] : v << 8;
		v = i + 2 < cbBuffer ? v << 8 | pBuffer[i + 2] : v << 8;*/

		pResult[j] = Base64Table[(v >> 18) & 0x3F];
		pResult[j + 1] = Base64Table[(v >> 12) & 0x3F];
		if (i + 1 < cbBuffer) {
			pResult[j + 2] = Base64Table[(v >> 6) & 0x3F];
		}
		else {
			pResult[j + 2] = '=';
		}
		if (i + 2 < cbBuffer) {
			pResult[j + 3] = Base64Table[v & 0x3F];
		}
		else {
			pResult[j + 3] = '=';
		}
	}

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

PBUFFER Base64Decode
(
	_In_ LPSTR lpInput
)
{
	DWORD cbInput = lstrlenA(lpInput);
	PBUFFER pResult = NULL;

	pResult = ALLOC(sizeof(BUFFER));
	if (!CryptStringToBinaryA(lpInput, cbInput, CRYPT_STRING_BASE64, NULL, &pResult->cbBuffer, NULL, NULL)) {
		LOG_ERROR("CryptStringToBinaryA", GetLastError());
		return NULL;
	}

	pResult->pBuffer = ALLOC(pResult->cbBuffer + 1);
	if (!CryptStringToBinaryA(lpInput, cbInput, CRYPT_STRING_BASE64, pResult->pBuffer, &pResult->cbBuffer, NULL, NULL)) {
		LOG_ERROR("CryptStringToBinaryA", GetLastError());
		FreeBuffer(pResult);
		return NULL;
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
	FREE(pMatchedPositions);

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
	FREE(pMatchedPositions);

	return lpResult;
}

LPSTR GenGUIDStrA(VOID) {
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
	FREE(lpOutput);

	return lpResult;
}

LPWSTR GenGUIDStrW(VOID) {
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
	FREE(lpOutput);

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

	lpPos = StrStrW(&lpInput[cbInput - cbMatchedStr], lpMatchedStr);
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

	lpPos = StrStrA(&lpInput[cbInput - cbMatchedStr], lpMatchedStr);
	if (lpPos == NULL) {
		return FALSE;
	}

	if (lstrlenA(lpPos) != cbMatchedStr) {
		return FALSE;
	}

	return TRUE;
}

LPWSTR TrimSuffixW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpSuffix,
	_In_ BOOL Recursive
)
{
	LPWSTR lpPos = NULL;
	LPWSTR lpResult = NULL;
	DWORD dwPos = 0;
	DWORD cbSuffix = lstrlenW(lpSuffix);

	lpResult = DuplicateStrW(lpInput, 0);
	while (TRUE) {
		if (!IsStrEndsWithW(lpResult, lpSuffix)) {
			break;
		}

		dwPos = lstrlenW(lpResult) - cbSuffix;
		RtlSecureZeroMemory(&lpResult[dwPos], cbSuffix * sizeof(WCHAR));
		if (!Recursive) {
			break;
		}
	}

	return lpResult;
}

LPSTR TrimSuffixA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpSuffix,
	_In_ BOOL Recursive
)
{
	LPSTR lpPos = NULL;
	LPSTR lpResult = NULL;
	DWORD dwPos = 0;
	DWORD cbSuffix = lstrlenA(lpSuffix);

	lpResult = DuplicateStrA(lpInput, 0);
	while (TRUE) {
		if (!IsStrEndsWithA(lpResult, lpSuffix)) {
			break;
		}

		dwPos = lstrlenA(lpResult) - cbSuffix;
		RtlSecureZeroMemory(&lpResult[dwPos], cbSuffix);
		if (!Recursive) {
			break;
		}
	}

	return lpResult;
}

LPWSTR TrimPrefixW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpPrefix,
	_In_ BOOL Recursive
)
{
	LPWSTR lpResult = NULL;
	DWORD dwPos = 0;
	DWORD cbPrefix = lstrlenW(lpPrefix);

	if (!IsStrStartsWithW(lpInput, lpPrefix)) {
		return NULL;
	}

	while (TRUE) {
		if (!IsStrStartsWithW(&lpInput[dwPos], lpPrefix)) {
			break;
		}

		dwPos += cbPrefix;
		if (!Recursive) {
			break;
		}
	}

	lpResult = DuplicateStrW(&lpInput[dwPos], 0);
	return lpResult;
}

LPSTR TrimPrefixA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpPrefix,
	_In_ BOOL Recursive
)
{
	LPSTR lpResult = NULL;
	DWORD dwPos = 0;
	DWORD cbPrefix = lstrlenA(lpPrefix);

	if (!IsStrStartsWithA(lpInput, lpPrefix)) {
		return NULL;
	}

	while (TRUE) {
		if (!IsStrStartsWithA(&lpInput[dwPos], lpPrefix)) {
			break;
		}

		dwPos += cbPrefix;
		if (!Recursive) {
			break;
		}
	}

	lpResult = DuplicateStrA(&lpInput[dwPos], 0);
	return lpResult;
}

LPWSTR TrimStrW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpSubStr,
	_In_ BOOL Recursive
)
{
	LPWSTR lpTemp = NULL;
	LPWSTR lpResult = NULL;

	lpTemp = TrimSuffixW(lpInput, lpSubStr, Recursive);
	if (lpTemp == NULL) {
		lpTemp = DuplicateStrW(lpInput, 0);
	}

	lpResult = TrimPrefixW(lpTemp, lpSubStr, Recursive);
	if (lpResult == NULL) {
		lpResult = DuplicateStrW(lpTemp, 0);
	}

	FREE(lpTemp);
	return lpResult;
}

LPSTR TrimStrA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpSubStr,
	_In_ BOOL Recursive
)
{
	LPSTR lpTemp = NULL;
	LPSTR lpResult = NULL;

	lpTemp = TrimSuffixA(lpInput, lpSubStr, Recursive);
	if (lpTemp == NULL) {
		lpTemp = DuplicateStrA(lpInput, 0);
	}

	lpResult = TrimPrefixA(lpTemp, lpSubStr, Recursive);
	if (lpResult == NULL) {
		lpResult = DuplicateStrA(lpTemp, 0);
	}

	FREE(lpTemp);
	return lpResult;
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

DWORD CountNumOfMatchedStrA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpSubStr
)
{
	PDWORD pMatchedPositions = NULL;
	DWORD cbInput = lstrlenA(lpInput);
	DWORD cbMatchedStr = lstrlenA(lpSubStr);
	DWORD i = 0;
	DWORD dwNumOfMatches = 0;
	LPSTR lpTemp = NULL;

	pMatchedPositions = ALLOC(sizeof(DWORD) * (cbInput / cbMatchedStr));
	for (i = 0; i < cbInput / cbMatchedStr; i++) {
		pMatchedPositions[i] = -1;
		if (i == 0) {
			lpTemp = StrStrA(lpInput, lpSubStr);
			if (lpTemp == NULL) {
				break;
			}

			pMatchedPositions[i] = lpTemp - lpInput;
		}
		else {
			if (pMatchedPositions[i] + cbMatchedStr >= cbInput) {
				break;
			}

			lpTemp = StrStrA(lpInput + pMatchedPositions[i - 1] + cbMatchedStr, lpSubStr);
			if (lpTemp == NULL) {
				break;
			}

			pMatchedPositions[i] = lpTemp - lpInput;
		}

		if (pMatchedPositions[i] != -1) {
			dwNumOfMatches++;
		}
	}

CLEANUP:
	FREE(pMatchedPositions);

	return dwNumOfMatches;
}

DWORD CountNumOfMatchedStrW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpSubStr
)
{
	PDWORD pMatchedPositions = NULL;
	DWORD cbInput = lstrlenW(lpInput);
	DWORD cbMatchedStr = lstrlenW(lpSubStr);
	DWORD i = 0;
	DWORD dwNumOfMatches = 0;
	LPWSTR lpTemp = NULL;

	pMatchedPositions = ALLOC(sizeof(DWORD) * (cbInput / cbMatchedStr));
	for (i = 0; i < cbInput / cbMatchedStr; i++) {
		pMatchedPositions[i] = -1;
		if (i == 0) {
			lpTemp = StrStrW(lpInput, lpSubStr);
			if (lpTemp == NULL) {
				break;
			}

			pMatchedPositions[i] = lpTemp - lpInput;
		}
		else {
			if (pMatchedPositions[i] + cbMatchedStr >= cbInput) {
				break;
			}

			lpTemp = StrStrW(lpInput + pMatchedPositions[i - 1] + cbMatchedStr, lpSubStr);
			if (lpTemp == NULL) {
				break;
			}

			pMatchedPositions[i] = lpTemp - lpInput;
		}

		if (pMatchedPositions[i] != -1) {
			dwNumOfMatches++;
		}
	}

CLEANUP:
	FREE(pMatchedPositions);

	return dwNumOfMatches;
}

LPWSTR* StrSplitNW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpSubStr,
	_In_ DWORD dwReturnedCount,
	_Out_opt_ PDWORD pcbSplittedArray
)
{
	DWORD dwNumOfMatches = 0;
	LPWSTR* pResult = NULL;
	DWORD i = 0;
	LPWSTR lpTemp = NULL;
	LPWSTR lpOldTemp = NULL;
	LPWSTR lpMatchedPos = NULL;
	DWORD cbSubStr = lstrlenW(lpSubStr);
	DWORD cbSplittedArray = 0;

	lpTemp = TrimStrW(lpInput, lpSubStr, TRUE);
	dwNumOfMatches = CountNumOfMatchedStrW(lpTemp, lpSubStr);
	lpOldTemp = lpTemp;
	if (dwNumOfMatches == 0) {
		return NULL;
	}

	if (dwReturnedCount > dwNumOfMatches + 1 && pcbSplittedArray == NULL) {
		goto CLEANUP;
	}

	pResult = ALLOC((dwNumOfMatches + 1) * sizeof(LPWSTR));
	for (i = 0; i <= dwNumOfMatches; i++) {
		lpMatchedPos = StrStrW(lpTemp, lpSubStr);
		if (lpMatchedPos == NULL) {
			pResult[i] = DuplicateStrW(lpTemp, 0);
			cbSplittedArray++;
			break;
		}

		if (lpMatchedPos == lpTemp) {
			lpTemp += cbSubStr;
			i--;
			continue;
		}

		lpMatchedPos[0] = L'\0';
		pResult[i] = DuplicateStrW(lpTemp, 0);
		lpTemp = lpMatchedPos + cbSubStr;
		cbSplittedArray++;
	}

	if (pcbSplittedArray != NULL) {
		if (dwReturnedCount > 0) {
			*pcbSplittedArray = dwReturnedCount;
		}
		else {
			*pcbSplittedArray = cbSplittedArray;
		}
	}

CLEANUP:
	FREE(lpOldTemp);

	return pResult;
}

LPSTR* StrSplitNA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpSubStr,
	_In_ DWORD dwReturnedCount,
	_Out_opt_ PDWORD pcbSplittedArray
)
{
	DWORD dwNumOfMatches = 0;
	LPSTR* pResult = NULL;
	DWORD i = 0;
	LPSTR lpTemp = NULL;
	LPSTR lpOldTemp = NULL;
	LPSTR lpMatchedPos = NULL;
	DWORD cbSubStr = lstrlenA(lpSubStr);
	DWORD cbSplittedArray = 0;

	lpTemp = TrimStrA(lpInput, lpSubStr, TRUE);
	dwNumOfMatches = CountNumOfMatchedStrA(lpTemp, lpSubStr);
	lpOldTemp = lpTemp;
	if (dwNumOfMatches == 0) {
		return NULL;
	}

	if (dwReturnedCount > dwNumOfMatches + 1 && pcbSplittedArray == NULL) {
		goto CLEANUP;
	}

	pResult = ALLOC((dwNumOfMatches + 1) * sizeof(LPSTR));
	for (i = 0; i <= dwNumOfMatches; i++) {
		lpMatchedPos = StrStrA(lpTemp, lpSubStr);
		if (lpMatchedPos == NULL) {
			pResult[i] = DuplicateStrA(lpTemp, 0);
			cbSplittedArray++;
			break;
		}

		if (lpMatchedPos == lpTemp) {
			lpTemp += cbSubStr;
			i--;
			continue;
		}

		lpMatchedPos[0] = '\0';
		pResult[i] = DuplicateStrA(lpTemp, 0);
		lpTemp = lpMatchedPos + cbSubStr;
		cbSplittedArray++;
	}

	if (pcbSplittedArray != NULL) {
		if (dwReturnedCount > 0) {
			*pcbSplittedArray = dwReturnedCount;
		}
		else {
			*pcbSplittedArray = cbSplittedArray;
		}
	}

CLEANUP:
	FREE(lpOldTemp);

	return pResult;
}

LPWSTR ExtractSubStrW
(
	_In_ LPWSTR lpInput,
	_In_ DWORD cbInput
)
{
	LPWSTR lpResult = NULL;

	lpResult = ALLOC((cbInput + 1) * sizeof(WCHAR));
	memcpy(lpResult, lpInput, cbInput * sizeof(WCHAR));
	return lpResult;
}

LPSTR ExtractSubStrA
(
	_In_ LPSTR lpInput,
	_In_ DWORD cbInput
)
{
	LPSTR lpResult = NULL;

	lpResult = ALLOC(cbInput + 1);
	memcpy(lpResult, lpInput, cbInput);
	return lpResult;
}

VOID GoDump
(
	_In_ PBYTE pInput,
	_In_ DWORD cbInput,
	_In_ LPSTR lpPrefix
)
{
	DWORD i = 0;

	PrintFormatA("%s: [", lpPrefix);
	for (i = 0; i < cbInput; i++) {
		PrintFormatA("%d ", pInput[i]);
	}

	PrintFormatA("]\n");
}

LPSTR StrCatExA
(
	_In_ LPSTR lpStr1,
	_In_ LPSTR lpStr2
)
{
	DWORD cchResult = lstrlenA(lpStr1) + lstrlenA(lpStr2);

	if (lpStr1 == NULL) {
		lpStr1 = ALLOC(cchResult + 1);
	}
	else {
		lpStr1 = REALLOC(lpStr1, cchResult + 1);
	}

	lstrcatA(lpStr1, lpStr2);
	lpStr1[cchResult] = '\0';
	return lpStr1;
}

LPWSTR StrCatExW
(
	_In_ LPWSTR lpStr1,
	_In_ LPWSTR lpStr2
)
{
	DWORD cchResult = lstrlenW(lpStr1) + lstrlenW(lpStr2);

	if (lpStr1 == NULL) {
		lpStr1 = ALLOC((cchResult + 1) * sizeof(WCHAR));
	}
	else {
		lpStr1 = REALLOC(lpStr1, (cchResult + 1) * sizeof(WCHAR));
	}

	lstrcatW(lpStr1, lpStr2);
	lpStr1[cchResult] = L'\0';
	return lpStr1;
}

LPSTR GetNameFromPathA
(
	_In_ LPSTR lpPath
)
{
	LPSTR lpClonedPath = DuplicateStrA(lpPath, 0);
	LPSTR lpName = NULL;
	DWORD cchName = 0;

	lpName = PathFindFileNameA(lpClonedPath);
	cchName = lstrlenA(lpName);
	memcpy(lpClonedPath, lpName, cchName + 1);
	lpClonedPath = REALLOC(lpClonedPath, cchName + 1);
	return lpClonedPath;
}

LPWSTR GetNameFromPathW
(
	_In_ LPWSTR lpPath
)
{
	LPWSTR lpClonedPath = DuplicateStrW(lpPath, 0);
	LPWSTR lpName = NULL;
	DWORD cchName = 0;

	lpName = PathFindFileNameW(lpClonedPath);
	cchName = lstrlenW(lpName);
	memcpy(lpClonedPath, lpName, (cchName + 1) * sizeof(WCHAR));
	lpClonedPath = REALLOC(lpClonedPath, (cchName + 1) * sizeof(WCHAR));
	return lpClonedPath;
}

LPSTR ConvertBytesToHexA
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer
)
{
	LPSTR lpResult = NULL;
	DWORD i = 0;

	lpResult = ALLOC((2 * cbBuffer) + 1);
	for (i = 0; i < cbBuffer; i++) {
		wsprintfA(&lpResult[i * 2], "%02x", pBuffer[i]);
	}

	return lpResult;
}

LPWSTR ConvertBytesToHexW
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer
)
{
	LPWSTR lpResult = NULL;
	DWORD i = 0;

	lpResult = ALLOC(((2 * cbBuffer) + 1) * sizeof(WCHAR));
	for (i = 0; i < cbBuffer; i++) {
		wsprintfW(&lpResult[i * 2], L"%02x", pBuffer[i]);
	}

	return lpResult;
}

LPWSTR StrInsertBeforeW
(
	_In_ LPWSTR lpStr1,
	_In_ LPWSTR lpStr2
)
{
	LPWSTR lpResult = NULL;

	if (lpStr1 == NULL || lpStr2 == NULL) {
		return NULL;
	}

	lpResult = DuplicateStrW(lpStr2, lstrlenW(lpStr1));
	lstrcatW(lpResult, lpStr1);
	FREE(lpStr1);

	return lpResult;
}

LPSTR StrInsertBeforeA
(
	_In_ LPSTR lpStr1,
	_In_ LPSTR lpStr2
)
{
	LPSTR lpResult = NULL;

	if (lpStr1 == NULL || lpStr2 == NULL) {
		return NULL;
	}

	lpResult = DuplicateStrA(lpStr2, lstrlenA(lpStr1));
	lstrcatA(lpResult, lpStr1);
	FREE(lpStr1);

	return lpResult;
}

LPSTR UpperCaseA
(
	_In_ LPSTR lpInput
)
{
	DWORD i = 0;
	CHAR c = '\0';
	LPSTR lpResult = NULL;

	lpResult = DuplicateStrA(lpInput, 0);
	for (i = 0; i < lstrlenA(lpInput); i++) {
		c = lpInput[i];
		if (c >= 'a' && c <= 'z') {
			lpResult[i] = c - 'a' + 'A';
		}
	}

	return lpResult;
}

LPWSTR UpperCaseW
(
	_In_ LPWSTR lpInput
)
{
	DWORD i = 0;
	WCHAR c = L'\0';
	LPWSTR lpResult = NULL;

	lpResult = DuplicateStrW(lpInput, 0);
	for (i = 0; i < lstrlenW(lpInput); i++) {
		c = lpInput[i];
		if (c >= L'a' && c <= L'z') {
			lpResult[i] = c - L'a' + L'A';
		}
	}

	return lpResult;
}