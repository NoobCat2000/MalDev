#pragma once

DWORD GenRandomNumber32
(
    _In_ DWORD dwMin,
    _In_ DWORD dwMax
);

PBYTE GenRandomStr
(
    _In_ DWORD dwLength
);

PBYTE GenRandomBytes
(
    _In_ DWORD dwSize
);

CHAR GenRandomDigit
(
    _In_ BOOL IsUpperCase
);