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
	_In_ DWORD dwLength
);

LPSTR DuplicateStrA
(
	_In_ LPSTR lpInput,
	_In_ DWORD dwLength
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