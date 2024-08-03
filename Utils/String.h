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