#pragma once

BOOL QueryRegValue
(
	_In_ HKEY hRootKey,
	_In_ LPWSTR lpSubKey,
	_In_ LPWSTR lpValueName,
	_Out_ PBYTE* pOutput,
	_Out_ PDWORD pcbOutput
);