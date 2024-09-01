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

BOOL GetOsVersion
(
    PRTL_OSVERSIONINFOW lpVersionInformation
);