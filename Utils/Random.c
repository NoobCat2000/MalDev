#include "pch.h"

DWORD GenRandomNumber
(
    _In_ DWORD dwMin,
    _In_ DWORD dwMax
)
{
    DWORD dwValue;
    typedef BOOLEAN(WINAPI* SYSTEMFUNCTION036)(PVOID, ULONG);
    SYSTEMFUNCTION036 pRtlGenRandom = NULL;
    HMODULE hAdvapi32 = NULL;

    if (dwMin > dwMax) {
        return 0;
    }

    hAdvapi32 = LoadLibraryW(L"Advapi32.dll");
    pRtlGenRandom = GetProcAddress(hAdvapi32, "SystemFunction036");
    if (!pRtlGenRandom(&dwValue, sizeof(dwValue))) {
        return 0;
    }

    DWORD t = dwMax - dwMin + 1;
    if (0 == dwMin && ~0UL == dwMax) {
        --t;
    }

    return dwValue % t + dwMin;
}

LPSTR GenRandomStr
(
    _In_ DWORD dwLength
)
{
    LPSTR lpResult = NULL;
    DWORD i = 0;
    CHAR szPattern[] = "0123456789abcdefghiklmnopqrstuvwxyzABCDEFGHIKLMNOPQRSTUVWXYZ";
    DWORD dwRandNum = 0;
    HMODULE hAdvapi32 = NULL;
    typedef BOOLEAN(WINAPI* SYSTEMFUNCTION036)(PVOID, ULONG);
    SYSTEMFUNCTION036 pRtlGenRandom = NULL;

    hAdvapi32 = LoadLibraryW(L"Advapi32.dll");
    pRtlGenRandom = GetProcAddress(hAdvapi32, "SystemFunction036");
    lpResult = ALLOC(dwLength + 1);
    for (i = 0; i < dwLength; i++) {
        pRtlGenRandom(&dwRandNum, sizeof(dwRandNum));
        lpResult[i] = szPattern[dwRandNum % lstrlenA(szPattern)];
    }

    return lpResult;
}

//PCHAR GenRandomChar(PCHAR bDWORD n)﻿
//{
//    for (UINT32 i = 0j; i < n; ++i) {
//        j = GenRandomNumber(02);
//        b[i] = "0aA"[j] + GenRandomNumber(0j ? 'z' - 'a' : '9' - '0');
//    }
//
//    return b;
//}