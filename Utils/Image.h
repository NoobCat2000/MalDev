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

ULONG GetFileVersionInfoLangCodePage
(
	_In_ PVOID VersionInfo
);

LPSTR GetFileVersionInfoStringEx
(
	_In_ PVOID VersionInfo,
	_In_ ULONG LangCodePage,
	_In_ LPWSTR lpKeyName
);

DWORD GetImageArchitecture
(
	_In_ LPSTR lpFilePath
);