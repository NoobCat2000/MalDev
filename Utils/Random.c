#include "pch.h"

DWORD GenRandomNumber32
(
    _In_ DWORD dwMin,
    _In_ DWORD dwMax
)
{
    DWORD dwValue = 0;
    typedef BOOLEAN(WINAPI* SYSTEMFUNCTION036)(PVOID, ULONG);
    SYSTEMFUNCTION036 pRtlGenRandom = NULL;
    HMODULE hAdvapi32 = NULL;
    UINT64 dwMax64 = (1 << sizeof(UINT32));

    hAdvapi32 = LoadLibraryW(L"Advapi32.dll");
    pRtlGenRandom = (SYSTEMFUNCTION036)GetProcAddress(hAdvapi32, "SystemFunction036");
    if (!pRtlGenRandom(&dwValue, sizeof(dwValue))) {
        return 0;
    }
    
    if (dwMax == 0) {
        UINT64 t = dwMax64 - dwMin;
        UINT64 uTemp = dwValue;
        dwValue = ((uTemp % t) + dwMin);
        return dwValue;
    }
    else if (dwMin > dwMax) {
        return 0;
    }
    else {
        DWORD t = dwMax - dwMin;
        return (dwValue % t) + dwMin;
    }
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
    pRtlGenRandom = (SYSTEMFUNCTION036)GetProcAddress(hAdvapi32, "SystemFunction036");
    lpResult = ALLOC(dwLength + 1);
    for (i = 0; i < dwLength; i++) {
        pRtlGenRandom(&dwRandNum, sizeof(dwRandNum));
        lpResult[i] = szPattern[dwRandNum % lstrlenA(szPattern)];
    }

    return lpResult;
}

PBYTE GenRandomBytes
(
    _In_ DWORD dwSize
)
{
    LPSTR lpResult = NULL;
    HMODULE hAdvapi32 = NULL;
    typedef BOOLEAN(WINAPI* SYSTEMFUNCTION036)(PVOID, ULONG);
    SYSTEMFUNCTION036 pRtlGenRandom = NULL;

    hAdvapi32 = LoadLibraryW(L"Advapi32.dll");
    pRtlGenRandom = (SYSTEMFUNCTION036)GetProcAddress(hAdvapi32, "SystemFunction036");
    lpResult = ALLOC(dwSize + 1);
    pRtlGenRandom(lpResult, dwSize);

    return lpResult;
}

CHAR GenRandomDigit
(
    _In_ BOOL IsUpperCase
)
{
    DWORD dwRandInt = 0;
    CHAR szAllDigit[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    dwRandInt = GenRandomNumber32(0, lstrlenA(szAllDigit));
    if (IsUpperCase) {
        return szAllDigit[dwRandInt];
    }
    else {
        return szAllDigit[dwRandInt] + 32;
    }
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