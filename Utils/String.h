#pragma once

LPWSTR ConvertCharToWchar
(
	_In_ LPSTR lpInput
);

LPSTR ConvertWcharToChar
(
	_In_ LPWSTR lpInput
);

LPWSTR DuplicateStrW
(
	_In_ LPWSTR lpInput,
	_In_ DWORD dwAdditionalLength
);

LPSTR DuplicateStrA
(
	_In_ LPSTR lpInput,
	_In_ DWORD dwAdditionalLength
);

LPSTR SearchMatchStrA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpStartsWith,
	_In_ LPSTR lpEndsWith
);

LPSTR SearchMatchStrW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpStartsWith,
	_In_ LPWSTR lpEndsWith
);

LPSTR ConvertToHexString
(
	_In_ PBYTE pInput,
	_In_ DWORD cbInput
);

PBYTE FromHexString
(
	_In_ LPSTR lpHexString
);

LPSTR Base64Encode
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer,
	_In_ BOOL IsStrict
);

LPWSTR StrConcatenateW
(
	_In_ LPWSTR lpString1,
	_In_ LPWSTR lpString2
);

LPSTR StrConcatenateA
(
	_In_ LPSTR lpString1,
	_In_ LPSTR lpString2
);

LPWSTR StrInsertW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpInsertedStr,
	_In_ DWORD dwPos
);

LPSTR StrInsertA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpInsertedStr,
	_In_ DWORD dwPos
);

LPWSTR StrReplaceW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpMatchedStr,
	_In_ LPWSTR lpReplacedStr,
	_In_ BOOL IsReplaceAll,
	_In_ DWORD dwIdxOfOccurence
);

LPSTR StrReplaceA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpMatchedStr,
	_In_ LPSTR lpReplacedStr,
	_In_ BOOL IsReplaceAll,
	_In_ DWORD dwIdxOfOccurence
);

LPSTR GenGUIDStrA();

LPWSTR GenGUIDStrW();

BOOL IsStrStartsWithA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpMatchedStr
);

BOOL IsStrStartsWithW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpMatchedStr
);

BOOL IsStrEndsWithW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpMatchedStr
);

BOOL IsStrEndsWithA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpMatchedStr
);

LPWSTR TrimSuffixW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpSuffix,
	_In_ BOOL Recursive
);

LPSTR TrimSuffixA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpSuffix,
	_In_ BOOL Recursive
);

LPSTR StrInsertCharA
(
	_In_ LPSTR lpInput,
	_In_ CHAR CharValue,
	_In_ DWORD dwPos
);

LPWSTR StrInsertCharW
(
	_In_ LPWSTR lpInput,
	_In_ WCHAR CharValue,
	_In_ DWORD dwPos
);

PBYTE Base64Decode
(
	_In_ LPSTR lpInput,
	_Out_ PDWORD pcbOutput
);

LPWSTR* StrSplitNW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpSubStr,
	_In_ DWORD dwReturnedCount,
	_Out_opt_ PDWORD pcbSplittedArray
);

LPSTR* StrSplitNA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpSubStr,
	_In_ DWORD dwReturnedCount,
	_Out_opt_ PDWORD pcbSplittedArray
);

LPWSTR TrimStrW
(
	_In_ LPWSTR lpInput,
	_In_ LPWSTR lpSubStr,
	_In_ BOOL Recuresib
);

LPSTR TrimStrA
(
	_In_ LPSTR lpInput,
	_In_ LPSTR lpSubStr,
	_In_ BOOL Recuresib
);

LPWSTR ExtractSubStrW
(
	_In_ LPWSTR lpInput,
	_In_ DWORD cbInput
);

LPSTR ExtractSubStrA
(
	_In_ LPSTR lpInput,
	_In_ DWORD cbInput
);

VOID GoDump
(
	_In_ PBYTE pInput,
	_In_ DWORD cbInput,
	_In_ LPSTR lpPrefix
);

LPSTR StrCatExA
(
	_In_ LPSTR lpStr1,
	_In_ LPSTR lpStr2
);

LPWSTR StrCatExW
(
	_In_ LPWSTR lpStr1,
	_In_ LPWSTR lpStr2
);