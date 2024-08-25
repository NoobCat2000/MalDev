#pragma once

BOOL IsSystemLock();

LPSTR GetHostUUID();

LPSTR GetUserSID
(
    _In_ LPSTR lpUserName
);

LPSTR GetCurrentUserSID();

LPSTR GetComputerUserName();

LPSTR GetHostName();

BOOL GetVersionInfo
(
    PRTL_OSVERSIONINFOW lpVersionInformation
);