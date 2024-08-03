#pragma once

VOID SendControlInput
(
    _In_ WORD VkKey,
    _In_opt_ BOOL UseShift,
    _In_opt_ BOOL UseAlt
);

HWND GetWindowHandle
(
    _In_ DWORD dwPid,
    _In_ LPWSTR lpClassName,
    _In_opt_ LPWSTR lpWindowTitle,
    _In_ LPVOID lpProc
);

VOID SendStringInput
(
    _In_ LPSTR lpInput
);

BOOL CALLBACK EnumChildCallback
(
    _In_ HWND   hwnd,
    _In_ LPARAM lParam
);

VOID SendKeys
(
    _In_ LPWSTR lpString
);