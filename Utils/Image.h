#pragma once

typedef struct _VS_VERSION_INFO_STRUCT32
{
	USHORT Length;
	USHORT ValueLength;
	USHORT Type;
	WCHAR Key[1];
} VS_VERSION_INFO_STRUCT32, *PVS_VERSION_INFO_STRUCT32;

typedef struct _LANGANDCODEPAGE
{
	USHORT uLanguage;
	USHORT uCodePage;
} LANGANDCODEPAGE, * PLANGANDCODEPAGE;

PBYTE LoadImageResource
(
	_In_ LPVOID lpImageBase,
	_In_ LPWSTR lpName,
	_In_ LPWSTR lpType,
	_Out_opt_ PDWORD pcbResource
);

PBYTE LoadResourceCopy
(
	_In_ LPVOID lpImageBase,
	_In_ LPWSTR lpName,
	_In_ LPWSTR lpType,
	_Out_opt_ PDWORD pcbResource
);