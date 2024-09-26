#include "pch.h"

BOOL IsSystemLock(VOID)
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

LPSTR GetHostUUID(VOID) {
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

            LogError(L"LookupAccountNameA failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
            goto CLEANUP;
        }

        break;
    }

    if (!ConvertSidToStringSidA(pSid, &lpTemp)) {
        LogError(L"ConvertSidToStringSidA failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
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

LPSTR GetCurrentUserSID(VOID)
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

LPSTR GetComputerUserName(VOID)
{
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
                LogError(L"GetComputerNameExA failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
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
                    LogError(L"GetComputerNameExA failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
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
        LogError(L"GetUserNameA failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
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

LPSTR GetHostName(VOID)
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
                LogError(L"GetComputerNameExA failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
                goto CLEANUP;
            }
        }

        break;
    }

CLEANUP:
    return lpResult;
}

LPSTR GetPrimaryDnsSuffix(VOID)
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
                LogError(L"GetComputerNameExA failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, dwLastError);
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

DWORD GetWindowsVersionEx(VOID)
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

PNETWORK_CONNECTION GetNetworkConnections
(
    _Out_ PDWORD pNumberOfConnections
)
{
    HMODULE hDllModule = NULL;
    GETEXTENDEDTCPTABLE fnGetExtendedTcpTable = NULL;
    GETEXTENDEDUDPTABLE fnGetExtendedUdpTable = NULL;
    INTERNALGETBOUNDTCPENDPOINTTABLE fnInternalGetBoundTcpEndpointTable = NULL;
    INTERNALGETBOUNDTCP6ENDPOINTTABLE fnInternalGetBoundTcp6EndpointTable = NULL;
    PMIB_TCPTABLE_OWNER_MODULE pTcp4Table = NULL;
    PMIB_TCP6TABLE_OWNER_MODULE pTcp6Table = NULL;
    PMIB_UDPTABLE_OWNER_MODULE pUdp4Table = NULL;
    PMIB_UDP6TABLE_OWNER_MODULE pUdp6Table = NULL;
    PMIB_TCPTABLE2 pBoundTcpTable = NULL;
    PMIB_TCP6TABLE2 pBoundTcp6Table = NULL;
    ULONG uTableSize = 0;
    DWORD dwCount = 0;
    DWORD dwWindowsVersion = 0;
    HANDLE hHeap = NULL;
    PNETWORK_CONNECTION pConnections = NULL;
    DWORD i = 0;
    DWORD dwIndex = 0;

    hDllModule = LoadLibraryW(L"iphlpapi.dll");
    if (hDllModule == NULL) {
        LogError(L"LoadLibraryW failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
        goto CLEANUP;
    }

    fnGetExtendedTcpTable = (GETEXTENDEDTCPTABLE)GetProcAddress(hDllModule, "GetExtendedTcpTable");
    if (fnGetExtendedTcpTable == NULL) {
        LogError(L"GetProcAddress failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
        goto CLEANUP;
    }

    fnGetExtendedUdpTable = (GETEXTENDEDUDPTABLE)GetProcAddress(hDllModule, "GetExtendedUdpTable");
    if (fnGetExtendedUdpTable == NULL) {
        LogError(L"GetProcAddress failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
        goto CLEANUP;
    }

    fnInternalGetBoundTcpEndpointTable = (INTERNALGETBOUNDTCPENDPOINTTABLE)GetProcAddress(hDllModule, "InternalGetBoundTcpEndpointTable");
    fnInternalGetBoundTcp6EndpointTable = (INTERNALGETBOUNDTCP6ENDPOINTTABLE)GetProcAddress(hDllModule, "InternalGetBoundTcp6EndpointTable");
    fnGetExtendedTcpTable(NULL, &uTableSize, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0);
    pTcp4Table = ALLOC(uTableSize);
    if (fnGetExtendedTcpTable(pTcp4Table, &uTableSize, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0) == NO_ERROR) {
        dwCount += pTcp4Table->dwNumEntries;
    }
    else {
        LogError(L"fnGetExtendedTcpTable failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
        goto CLEANUP;
    }

    uTableSize = 0;
    fnGetExtendedTcpTable(NULL, &uTableSize, FALSE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0);
    pTcp6Table = ALLOC(uTableSize);
    if (fnGetExtendedTcpTable(pTcp6Table, &uTableSize, FALSE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0) == NO_ERROR) {
        dwCount += pTcp6Table->dwNumEntries;
    }
    else {
        LogError(L"fnGetExtendedTcpTable failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
        goto CLEANUP;
    }

    uTableSize = 0;
    fnGetExtendedUdpTable(NULL, &uTableSize, FALSE, AF_INET, UDP_TABLE_OWNER_MODULE, 0);
    pUdp4Table = ALLOC(uTableSize);
    if (fnGetExtendedUdpTable(pUdp4Table, &uTableSize, FALSE, AF_INET, UDP_TABLE_OWNER_MODULE, 0) == NO_ERROR) {
        dwCount += pUdp4Table->dwNumEntries;
    }
    else {
        LogError(L"fnGetExtendedUdpTable failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
        goto CLEANUP;
    }

    uTableSize = 0;
    fnGetExtendedUdpTable(NULL, &uTableSize, FALSE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0);
    pUdp6Table = ALLOC(uTableSize);
    if (fnGetExtendedUdpTable(pUdp6Table, &uTableSize, FALSE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0) == NO_ERROR) {
        dwCount += pUdp6Table->dwNumEntries;
    }
    else {
        LogError(L"fnGetExtendedUdpTable failed at %s. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
        goto CLEANUP;
    }

    dwWindowsVersion = GetWindowsVersionEx();
    hHeap = GetProcessHeap();
    if (dwWindowsVersion >= WINDOWS_10_RS5 && fnInternalGetBoundTcpEndpointTable != NULL && fnInternalGetBoundTcp6EndpointTable != NULL) {
        if (fnInternalGetBoundTcpEndpointTable(&pBoundTcpTable, hHeap, 0) == NO_ERROR) {
            dwCount += pBoundTcpTable->dwNumEntries;
        }
        else {
            pBoundTcpTable = NULL;
        }

        if (fnInternalGetBoundTcp6EndpointTable(&pBoundTcp6Table, hHeap, 0) == NO_ERROR) {
            dwCount += pBoundTcp6Table->dwNumEntries;
        }
        else {
            pBoundTcp6Table = NULL;
        }
    }
    
    pConnections = ALLOC(sizeof(NETWORK_CONNECTION) * dwCount);
    if (pTcp4Table != NULL) {
        for (i = 0; i < pTcp4Table->dwNumEntries; i++) {
            pConnections[dwIndex].uProtocolType = TCP4_NETWORK_PROTOCOL;
            pConnections[dwIndex].LocalEndpoint.Address.Type = IPV4_NETWORK_TYPE;
            pConnections[dwIndex].LocalEndpoint.Address.Ipv4 = pTcp4Table->table[i].dwLocalAddr;
            pConnections[dwIndex].LocalEndpoint.Port = _byteswap_ushort((USHORT)pTcp4Table->table[i].dwLocalPort);
            pConnections[dwIndex].RemoteEndpoint.Address.Type = IPV4_NETWORK_TYPE;
            pConnections[dwIndex].RemoteEndpoint.Address.Ipv4 = pTcp4Table->table[i].dwRemoteAddr;
            pConnections[dwIndex].RemoteEndpoint.Port = _byteswap_ushort((USHORT)pTcp4Table->table[i].dwRemotePort);
            pConnections[dwIndex].State = pTcp4Table->table[i].dwState;
            pConnections[dwIndex].ProcessId = UlongToHandle(pTcp4Table->table[i].dwOwningPid);
            pConnections[dwIndex].CreateTime = pTcp4Table->table[i].liCreateTimestamp;
            memcpy(pConnections[dwIndex].OwnerInfo, pTcp4Table->table[i].OwningModuleInfo, sizeof(ULONGLONG) * min(NETWORK_OWNER_INFO_SIZE, TCPIP_OWNING_MODULE_SIZE));
            dwIndex++;
        }
    }

    if (pTcp6Table != NULL) {
        for (i = 0; i < pTcp6Table->dwNumEntries; i++) {
            pConnections[dwIndex].uProtocolType = TCP6_NETWORK_PROTOCOL;
            pConnections[dwIndex].LocalEndpoint.Address.Type = IPV6_NETWORK_TYPE;
            memcpy(pConnections[dwIndex].LocalEndpoint.Address.Ipv6, pTcp6Table->table[i].ucLocalAddr, 16);
            pConnections[dwIndex].LocalEndpoint.Port = _byteswap_ushort((USHORT)pTcp6Table->table[i].dwLocalPort);
            pConnections[dwIndex].RemoteEndpoint.Address.Type = IPV6_NETWORK_TYPE;
            memcpy(pConnections[dwIndex].RemoteEndpoint.Address.Ipv6, pTcp6Table->table[i].ucRemoteAddr, 16);
            pConnections[dwIndex].RemoteEndpoint.Port = _byteswap_ushort((USHORT)pTcp6Table->table[i].dwRemotePort);
            pConnections[dwIndex].State = pTcp6Table->table[i].dwState;
            pConnections[dwIndex].ProcessId = UlongToHandle(pTcp6Table->table[i].dwOwningPid);
            pConnections[dwIndex].CreateTime = pTcp6Table->table[i].liCreateTimestamp;
            memcpy(pConnections[dwIndex].OwnerInfo, pTcp6Table->table[i].OwningModuleInfo, sizeof(ULONGLONG) * min(NETWORK_OWNER_INFO_SIZE, TCPIP_OWNING_MODULE_SIZE));
            pConnections[dwIndex].uLocalScopeId = pTcp6Table->table[i].dwLocalScopeId;
            pConnections[dwIndex].uRemoteScopeId = pTcp6Table->table[i].dwRemoteScopeId;
            dwIndex++;
        }
    }

    if (pUdp4Table != NULL) {
        for (i = 0; i < pUdp4Table->dwNumEntries; i++) {
            pConnections[dwIndex].uProtocolType = UDP4_NETWORK_PROTOCOL;
            pConnections[dwIndex].LocalEndpoint.Address.Type = IPV4_NETWORK_TYPE;
            pConnections[dwIndex].LocalEndpoint.Address.Ipv4 = pUdp4Table->table[i].dwLocalAddr;
            pConnections[dwIndex].LocalEndpoint.Port = _byteswap_ushort((USHORT)pUdp4Table->table[i].dwLocalPort);
            pConnections[dwIndex].RemoteEndpoint.Address.Type = 0;
            pConnections[dwIndex].State = 0;
            pConnections[dwIndex].ProcessId = UlongToHandle(pUdp4Table->table[i].dwOwningPid);
            pConnections[dwIndex].CreateTime = pUdp4Table->table[i].liCreateTimestamp;
            memcpy(pConnections[dwIndex].OwnerInfo, pUdp4Table->table[i].OwningModuleInfo, sizeof(ULONGLONG) * min(NETWORK_OWNER_INFO_SIZE, TCPIP_OWNING_MODULE_SIZE));
            dwIndex++;
        }
    }

    if (pUdp6Table != NULL) {
        for (i = 0; i < pUdp6Table->dwNumEntries; i++) {
            pConnections[dwIndex].uProtocolType = UDP6_NETWORK_PROTOCOL;
            pConnections[dwIndex].LocalEndpoint.Address.Type = IPV6_NETWORK_TYPE;
            memcpy(pConnections[dwIndex].LocalEndpoint.Address.Ipv6, pUdp6Table->table[i].ucLocalAddr, 16);
            pConnections[dwIndex].LocalEndpoint.Port = _byteswap_ushort((USHORT)pUdp6Table->table[i].dwLocalPort);
            pConnections[dwIndex].RemoteEndpoint.Address.Type = 0;
            pConnections[dwIndex].State = 0;
            pConnections[dwIndex].ProcessId = UlongToHandle(pUdp6Table->table[i].dwOwningPid);
            pConnections[dwIndex].CreateTime = pUdp6Table->table[i].liCreateTimestamp;
            memcpy(pConnections[dwIndex].OwnerInfo, pUdp6Table->table[i].OwningModuleInfo, sizeof(ULONGLONG) * min(NETWORK_OWNER_INFO_SIZE, TCPIP_OWNING_MODULE_SIZE));
            pConnections[dwIndex].uLocalScopeId = pUdp6Table->table[i].dwLocalScopeId;
            pConnections[dwIndex].uRemoteScopeId = 0;
            dwIndex++;
        }
    }

    if (pBoundTcpTable != NULL) {
        for (i = 0; i < pBoundTcpTable->dwNumEntries; i++) {
            pConnections[dwIndex].uProtocolType = TCP4_NETWORK_PROTOCOL;
            pConnections[dwIndex].LocalEndpoint.Address.Type = IPV4_NETWORK_TYPE;
            pConnections[dwIndex].LocalEndpoint.Address.Ipv4 = pBoundTcpTable->table[i].dwLocalAddr;
            pConnections[dwIndex].LocalEndpoint.Port = _byteswap_ushort((USHORT)pBoundTcpTable->table[i].dwLocalPort);
            pConnections[dwIndex].RemoteEndpoint.Address.Type = IPV4_NETWORK_TYPE;
            pConnections[dwIndex].RemoteEndpoint.Address.Ipv4 = pBoundTcpTable->table[i].dwRemoteAddr;
            pConnections[dwIndex].RemoteEndpoint.Port = _byteswap_ushort((USHORT)pBoundTcpTable->table[i].dwRemotePort);
            pConnections[dwIndex].State = pBoundTcpTable->table[i].dwState;
            pConnections[dwIndex].ProcessId = UlongToHandle(pBoundTcpTable->table[i].dwOwningPid);
            dwIndex++;
        }
    }

    if (pBoundTcp6Table != NULL) {
        for (i = 0; i < pBoundTcp6Table->dwNumEntries; i++) {
            pConnections[dwIndex].uProtocolType = TCP6_NETWORK_PROTOCOL;
            pConnections[dwIndex].LocalEndpoint.Address.Type = IPV6_NETWORK_TYPE;
            memcpy(pConnections[dwIndex].LocalEndpoint.Address.Ipv6, pBoundTcp6Table->table[i].LocalAddr.s6_addr, 16);
            pConnections[dwIndex].LocalEndpoint.Port = _byteswap_ushort((USHORT)pBoundTcp6Table->table[i].dwLocalPort);
            pConnections[dwIndex].RemoteEndpoint.Address.Type = IPV6_NETWORK_TYPE;
            memcpy(pConnections[dwIndex].RemoteEndpoint.Address.Ipv6, pBoundTcp6Table->table[i].RemoteAddr.s6_addr, 16);
            pConnections[dwIndex].RemoteEndpoint.Port = _byteswap_ushort((USHORT)pBoundTcp6Table->table[i].dwRemotePort);
            pConnections[dwIndex].State = pBoundTcp6Table->table[i].State;
            pConnections[dwIndex].ProcessId = UlongToHandle(pBoundTcp6Table->table[i].dwOwningPid);
            pConnections[dwIndex].uLocalScopeId = pBoundTcp6Table->table[i].dwLocalScopeId;
            pConnections[dwIndex].uRemoteScopeId = pBoundTcp6Table->table[i].dwRemoteScopeId;
            dwIndex++;
        }
    }

    if (pNumberOfConnections != NULL) {
        *pNumberOfConnections = dwCount;
    }

CLEANUP:
    if (pTcp4Table != NULL) {
        FREE(pTcp4Table);
    }

    if (pTcp6Table != NULL) {
        FREE(pTcp6Table);
    }

    if (pUdp4Table != NULL) {
        FREE(pUdp4Table);
    }

    if (pUdp6Table != NULL) {
        FREE(pUdp6Table);
    }

    if (pBoundTcpTable != NULL) {
        FREE(pBoundTcpTable);
    }

    if (pBoundTcp6Table != NULL) {
        FREE(pBoundTcp6Table);
    }

    return pConnections;
}