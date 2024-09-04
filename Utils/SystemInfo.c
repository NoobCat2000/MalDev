#include "pch.h"

BOOL IsSystemLock()
{
    HANDLE hServer = WTS_CURRENT_SERVER_HANDLE;
    DWORD dwSessionId = WTS_CURRENT_SESSION;
    PWTSINFOEXA pInfo = NULL;
    DWORD bytesReturned = 0;
    BOOL bResult = FALSE;

    if (WTSQuerySessionInformationA(hServer, dwSessionId, WTSSessionInfoEx, &pInfo, &bytesReturned)) {
        bResult = pInfo->Data.WTSInfoExLevel1.SessionFlags == WTS_SESSIONSTATE_LOCK;
        WTSFreeMemory(pInfo);
    }

    return bResult;
}

LPSTR GetHostUUID() {
    LPSTR lpResult = NULL;
    LPWSTR lpTemp = NULL;

    if (!QueryRegValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\HardwareConfig", L"LastConfig", &lpTemp, NULL)) {
        return NULL;
    }

    lpResult = ConvertWcharToChar(lpTemp);
    FREE(lpTemp);
    return lpResult;
}

LPSTR GetUserSID
(
    _In_ LPSTR lpFullyQualifiedName
)
{
    PSID pSid = NULL;
    DWORD cbSid = SECURITY_MAX_SID_SIZE;
    SID_NAME_USE SidUse = SidTypeInvalid;
    LPSTR lpResult = NULL;
    LPSTR lpTemp = NULL;
    DWORD cbReferencedDomainName = 0x100;
    LPSTR lpReferencedDomainName = NULL;
    DWORD dwLastError = 0;

    pSid = ALLOC(cbSid);
    lpReferencedDomainName = ALLOC(cbReferencedDomainName);
    while (TRUE) {
        if (!LookupAccountNameA(NULL, lpFullyQualifiedName, pSid, &cbSid, lpReferencedDomainName, &cbReferencedDomainName, &SidUse)) {
            dwLastError = GetLastError();
            if (dwLastError == ERROR_INSUFFICIENT_BUFFER) {
                pSid = REALLOC(pSid, cbSid);
                lpReferencedDomainName = REALLOC(lpReferencedDomainName, cbReferencedDomainName);
                continue;
            }

            LogError(L"LookupAccountNameA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
            goto CLEANUP;
        }

        break;
    }

    if (!ConvertSidToStringSidA(pSid, &lpTemp)) {
        LogError(L"ConvertSidToStringSidA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
        goto CLEANUP;
    }

    lpResult = DuplicateStrA(lpTemp, 0);
CLEANUP:
    if (pSid != NULL) {
        FREE(pSid);
    }

    if (lpReferencedDomainName != NULL) {
        FREE(lpReferencedDomainName);
    }

    if (lpTemp != NULL) {
        LocalFree(lpTemp);
    }

    return lpResult;
}

LPSTR GetCurrentUserSID()
{
    LPSTR lpComputerUserName = NULL;
    LPSTR lpResult = NULL;

    lpComputerUserName = GetComputerUserName();
    if (lpComputerUserName == NULL) {
        return NULL;
    }

    lpResult = GetUserSID(lpComputerUserName);
    FREE(lpComputerUserName);
    return lpResult;
}

LPSTR GetComputerUserName() {
    LPSTR lpComputerName = NULL;
    CHAR szUserName[UNLEN + 1];
    DWORD cbComputerName = MAX_COMPUTERNAME_LENGTH + UNLEN + 1;
    DWORD dwLastError = ERROR_SUCCESS;
    DWORD cbUserName = _countof(szUserName);
    LPSTR lpResult = NULL;

    lpComputerName = ALLOC(cbComputerName);
    while (TRUE) {
        SecureZeroMemory(lpComputerName, sizeof(cbComputerName));
        if (!GetComputerNameExA(ComputerNameDnsDomain, lpComputerName, &cbComputerName)) {
            dwLastError = GetLastError();
            if (dwLastError == ERROR_MORE_DATA) {
                lpComputerName = REALLOC(lpComputerName, cbComputerName + 1);
                continue;
            }
            else {
                LogError(L"GetComputerNameExA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
                goto CLEANUP;
            }
        }

        break;
    }

    if (cbComputerName == 0) {
        while (TRUE) {
            if (!GetComputerNameExA(ComputerNameNetBIOS, lpComputerName, &cbComputerName)) {
                dwLastError = GetLastError();
                if (dwLastError == ERROR_MORE_DATA) {
                    lpComputerName = REALLOC(lpComputerName, cbComputerName + 1);
                    continue;
                }
                else {
                    LogError(L"GetComputerNameExA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
                    goto CLEANUP;
                }
            }

            break;
        }
    }

    if (cbComputerName == 0) {
        goto CLEANUP;
    }
    
    SecureZeroMemory(szUserName, sizeof(szUserName));
    if (!GetUserNameA(szUserName, &cbUserName)) {
        LogError(L"GetUserNameA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
        goto CLEANUP;
    }

    lpResult = DuplicateStrA(lpComputerName, lstrlenA(szUserName) + 1);
    lstrcatA(lpResult, "\\");
    lstrcatA(lpResult, szUserName);
CLEANUP:
    if (lpComputerName != NULL) {
        FREE(lpComputerName);
    }

    return lpResult;
}

LPSTR GetHostName()
{
    DWORD cbHostName = 0xFF;
    DWORD dwLastError = ERROR_SUCCESS;
    LPSTR lpResult = NULL;

    lpResult = ALLOC(cbHostName + 1);
    while (TRUE) {
        if (!GetComputerNameExA(ComputerNameDnsHostname, lpResult, &cbHostName)) {
            dwLastError = GetLastError();
            if (dwLastError == ERROR_MORE_DATA) {
                lpResult = REALLOC(lpResult, cbHostName + 1);
                continue;
            }
            else {
                FREE(lpResult);
                lpResult = NULL;
                LogError(L"GetComputerNameExA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
                goto CLEANUP;
            }
        }

        break;
    }

CLEANUP:
    return lpResult;
}

LPSTR GetPrimaryDnsSuffix()
{
    DWORD cbResult = 0xFF;
    DWORD dwLastError = ERROR_SUCCESS;
    LPSTR lpResult = NULL;

    lpResult = ALLOC(cbResult + 1);
    while (TRUE) {
        if (!GetComputerNameExA(ComputerNameDnsDomain, lpResult, &cbResult)) {
            dwLastError = GetLastError();
            if (dwLastError == ERROR_MORE_DATA) {
                lpResult = REALLOC(lpResult, cbResult + 1);
                continue;
            }
            else {
                FREE(lpResult);
                lpResult = NULL;
                LogError(L"GetComputerNameExA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
                goto CLEANUP;
            }
        }

        break;
    }

CLEANUP:
    return lpResult;
}

BOOL GetOsVersion
(
    PRTL_OSVERSIONINFOW lpVersionInformation
)
{
    return RtlGetVersion(lpVersionInformation) == STATUS_SUCCESS;
}

DWORD GetWindowsVersionEx()
{
    ULONG uMajorVersion = 0;
    ULONG uMinorVersion = 0;
    ULONG uBuildVersion = 0;
    RTL_OSVERSIONINFOEXW VersionInfo;

    SecureZeroMemory(&VersionInfo, sizeof(VersionInfo));
    VersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
    if (!NT_SUCCESS(RtlGetVersion(&VersionInfo))) {
        return WINDOWS_ANCIENT;
    }


    uMajorVersion = VersionInfo.dwMajorVersion;
    uMinorVersion = VersionInfo.dwMinorVersion;
    uBuildVersion = VersionInfo.dwBuildNumber;

    if (uMajorVersion == 6 && uMinorVersion < 1 || uMajorVersion < 6) {
        return WINDOWS_ANCIENT;
    }
    else if (uMajorVersion == 6 && uMinorVersion == 1) {
        return WINDOWS_7;
    }
    else if (uMajorVersion == 6 && uMinorVersion == 2) {
        return WINDOWS_8;
    }
    else if (uMajorVersion == 6 && uMinorVersion == 3) {
        return WINDOWS_8_1;
    }
    else if (uMajorVersion == 10 && uMinorVersion == 0) {
        if (uBuildVersion > 26100) {
            return WINDOWS_NEW;
        }
        else if (uBuildVersion >= 26100) {
            return WINDOWS_11_24H2;
        }
        else if (uBuildVersion >= 22631) {
            return WINDOWS_11_23H2;
        }
        else if (uBuildVersion >= 22621) {
            return WINDOWS_11_22H2;
        }
        else if (uBuildVersion >= 22000) {
            return WINDOWS_11;
        }
        else if (uBuildVersion >= 19045) {
            return WINDOWS_10_22H2;
        }
        else if (uBuildVersion >= 19044) {
            return WINDOWS_10_21H2;
        }
        else if (uBuildVersion >= 19043) {
            return WINDOWS_10_21H1;
        }
        else if (uBuildVersion >= 19042) {
            return WINDOWS_10_20H2;
        }
        else if (uBuildVersion >= 19041) {
            return WINDOWS_10_20H1;
        }
        else if (uBuildVersion >= 18363) {
            return WINDOWS_10_19H2;
        }
        else if (uBuildVersion >= 18362) {
            return WINDOWS_10_19H1;
        }
        else if (uBuildVersion >= 17763) {
            return WINDOWS_10_RS5;
        }
        else if (uBuildVersion >= 17134) {
            return WINDOWS_10_RS4;
        }
        else if (uBuildVersion >= 16299) {
            return WINDOWS_10_RS3;
        }
        else if (uBuildVersion >= 15063) {
            return WINDOWS_10_RS2;
        }
        else if (uBuildVersion >= 14393) {
            return WINDOWS_10_RS1;
        }
        else if (uBuildVersion >= 10586) {
            return WINDOWS_10_TH2;
        }
        else if (uBuildVersion >= 10240) {
            return WINDOWS_10;
        }
        else {
            return WINDOWS_10;
        }
    }
    else {
        return WINDOWS_NEW;
    }
}