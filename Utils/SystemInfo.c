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

    if (!QueryRegValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\HardwareConfig", L"LastConfig", &lpResult, NULL)) {
        return NULL;
    }

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
    CHAR szUserName[UNLEN + 1];
    DWORD cbComputerName = MAX_COMPUTERNAME_LENGTH + UNLEN + 1;
    DWORD dwLastError = ERROR_SUCCESS;
    DWORD cbUserName = _countof(szUserName);
    LPSTR lpResult = NULL;

    lpResult = ALLOC(cbComputerName);
    while (TRUE) {
        SecureZeroMemory(lpResult, sizeof(cbComputerName));
        if (!GetComputerNameExA(ComputerNameDnsDomain, lpResult, &cbComputerName)) {
            dwLastError = GetLastError();
            if (dwLastError == ERROR_MORE_DATA) {
                lpResult = REALLOC(lpResult, cbComputerName + 1);
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
            if (!GetComputerNameExA(ComputerNameNetBIOS, lpResult, &cbComputerName)) {
                dwLastError = GetLastError();
                if (dwLastError == ERROR_MORE_DATA) {
                    lpResult = REALLOC(lpResult, cbComputerName + 1);
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
        if (lpResult != NULL) {
            FREE(lpResult);
            lpResult = NULL;
        }
    }
CLEANUP:
    return lpResult;
}