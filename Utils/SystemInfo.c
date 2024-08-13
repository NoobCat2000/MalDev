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

BOOL IsUserActive()
{
    POINT Point1;
    POINT Point2;

    while (TRUE) {
        RtlSecureZeroMemory(&Point1, sizeof(Point1));
        RtlSecureZeroMemory(&Point2, sizeof(Point2));

        GetCursorPos(&Point1);
        Sleep(7000);
    }
    
}