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
	lpInput[dwPos] = L'\0';

	lstrcpyW(lpResult, lpInput);
	lpInput[dwPos] = chBackup;
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
	lpInput[dwPos] = '\0';

	lstrcpyA(lpResult, lpInput);
	lpInput[dwPos] = chBackup;
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
				chTmp = lpInput[pMatchedPositions[i + 1]];
				lpInput[pMatchedPositions[i + 1]] = L'\0';
				lstrcatW(lpResult, lpInput + pMatchedPositions[i] + cbMatchedStr);
				lpInput[pMatchedPositions[i + 1]] = chTmp;
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
				chTmp = lpInput[pMatchedPositions[i + 1]];
				lpInput[pMatchedPositions[i + 1]] = '\0';
				lstrcatA(lpResult, lpInput + pMatchedPositions[i] + cbMatchedStr);
				lpInput[pMatchedPositions[i + 1]] = chTmp;
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
	CHAR chTmp = '\0';
	DWORD cbInput = lstrlenA(lpInput);
	DWORD cbMatchedStr = lstrlenA(lpMatchedStr);
	
	if (!lstrcmpA(lpInput, lpMatchedStr)) {
		return TRUE;
	}

	if (cbMatchedStr >= cbInput) {
		return FALSE;
	}

	chTmp = lpInput[cbMatchedStr];
	lpInput[cbMatchedStr] = '\0';
	if (!lstrcmpA(lpInput, lpMatchedStr)) {
		lpInput[cbMatchedStr] = chTmp;
		return TRUE;
	}

	lpInput[cbMatchedStr] = chTmp;
	return FALSE;
}

BOOL IsStrStartsWithW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpMatchedStr
)
{
	WCHAR chTmp = L'\0';
	DWORD cbInput = lstrlenW(lpInput);
	DWORD cbMatchedStr = lstrlenW(lpMatchedStr);

	if (!lstrcmpW(lpInput, lpMatchedStr)) {
		return TRUE;
	}

	if (cbMatchedStr >= cbInput) {
		return FALSE;
	}

	chTmp = lpInput[cbMatchedStr];
	lpInput[cbMatchedStr] = L'\0';
	if (!lstrcmpW(lpInput, lpMatchedStr)) {
		lpInput[cbMatchedStr] = chTmp;
		return TRUE;
	}

	lpInput[cbMatchedStr] = chTmp;
	return FALSE;
}

//LPSTR ConvertToDoubleSlash
//(
//	_In_ LPSTR lpInput
//)
//{
//	LPSTR lpResult = NULL;
//}