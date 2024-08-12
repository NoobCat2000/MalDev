#include "pch.h"

BOOL IsStateLock() {
    HANDLE hServer = WTS_CURRENT_SERVER_HANDLE;
    DWORD sessionId = WTS_CURRENT_SESSION;
    PWTSINFOA pInfo = NULL;
    DWORD bytesReturned = 0;

    // Query session information
    if (WTSQuerySessionInformationA(hServer, sessionId, WTSSessionInfo, (LPSTR*)&pInfo, &bytesReturned))
    {
        // Check the lock state
        if (pInfo->State == WTSActive)
        {
        }
        else if (pInfo->State == WTSLocked)
        {
        }
        else
        {
        }

        // Free the memory allocated for the session information
        WTSFreeMemory(pInfo);
    }
    else
    {
    }

    return 0;
}