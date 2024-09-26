#include "pch.h"

typedef struct _SEARCH_WND {
    HWND hWnd;
    ULONG ProcessId;
    LPWSTR lpClassName;
    LPWSTR lpWindowTitle;
    PROC lpCallback;
} SEARCH_WND, * PSEARCH_WND;

VOID SendControlInput
(
    _In_ WORD VkKey,
    _In_opt_ BOOL UseShift,
    _In_opt_ BOOL UseAlt
)
{
    INPUT ip;

    ip.type = INPUT_KEYBOARD;
    ip.ki.wScan = 0;
    ip.ki.time = 0;
    ip.ki.dwExtraInfo = 0;
    ip.ki.dwFlags = 0;

    if (UseShift) {
        ip.ki.wVk = VK_LSHIFT;
        SendInput(1, &ip, sizeof(INPUT));
    }
    else if (UseAlt) {
        ip.ki.wVk = VK_LMENU;
        SendInput(1, &ip, sizeof(INPUT));
    }

    ip.ki.wVk = VkKey;
    SendInput(1, &ip, sizeof(INPUT));

    ip.ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(1, &ip, sizeof(INPUT));

    if (UseShift) {
        ip.ki.wVk = VK_LSHIFT;
        ip.ki.dwFlags = KEYEVENTF_KEYUP;
        SendInput(1, &ip, sizeof(INPUT));
    }
    else if (UseAlt) {
        ip.ki.wVk = VK_LMENU;
        ip.ki.dwFlags = KEYEVENTF_KEYUP;
        SendInput(1, &ip, sizeof(INPUT));
    }
}

VOID SendStringInput
(
    _In_ LPSTR lpInput
)
{
    UINT32 i = 0;
    for (i = 0; i < lstrlenW(lpInput); i++) {
        if (lpInput[i] >= 'a' && lpInput[i] <= 'z') {
            lpInput[i] -= 0x20;
        }
        
        if (lpInput[i] >= 'A' && lpInput[i] <= 'Z') {
            SendControlInput(lpInput[i], FALSE, FALSE);
        }
        else if (lpInput[i] >= '0' && lpInput[i] <= '9') {
            SendControlInput(lpInput[i], FALSE, FALSE);
        }
        else if (lpInput[i] == ":") {
            SendControlInput(VK_OEM_1, TRUE, FALSE);
        }
        else if (lpInput[i] == "\\") {
            SendControlInput(VK_OEM_5, FALSE, FALSE);
        }
    }
}

BOOL CALLBACK EnumWindowsCallback
(
    _In_ HWND   hwnd,
    _In_ LPARAM lParam
)
{
    PSEARCH_WND SearchWnd = (PSEARCH_WND)lParam;
    WCHAR wszClassName[0x400];
    WCHAR wszWindowTitle[0x400];
    DWORD dwPid;

    GetWindowThreadProcessId(hwnd, &dwPid);
    if (dwPid == SearchWnd->ProcessId) {
        if (SearchWnd->lpWindowTitle != NULL && GetWindowTextW(hwnd, wszWindowTitle, _countof(wszWindowTitle))) {
            if (StrCmpW(wszWindowTitle, SearchWnd->lpWindowTitle) != 0) {
                return TRUE;
            }
        }

        if (SearchWnd->lpClassName != NULL && GetClassNameW(hwnd, wszClassName, _countof(wszClassName))) {
            if (StrCmpW(wszClassName, SearchWnd->lpClassName) != 0) {
                return TRUE;
            }
        }

        SearchWnd->hWnd = hwnd;
        if (SearchWnd->lpCallback != NULL) {
            SearchWnd->lpCallback();
        }

        return FALSE;
    }

    return TRUE;
}

HWND GetWindowHandle
(
    _In_ DWORD dwPid,
    _In_ LPWSTR lpClassName,
    _In_opt_ LPWSTR lpWindowTitle,
    _In_ LPVOID lpProc
)
{
    SEARCH_WND SearchWnd;
    
    SecureZeroMemory(&SearchWnd, sizeof(SearchWnd));
    SearchWnd.ProcessId = dwPid;
    SearchWnd.hWnd = NULL;
    SearchWnd.lpClassName = lpClassName;
    SearchWnd.lpWindowTitle = lpWindowTitle;
    SearchWnd.lpCallback = lpProc;
    if (!EnumWindows(EnumWindowsCallback, (LPARAM)(&SearchWnd))) {
        goto END;
    }

END:
    return SearchWnd.hWnd;
}

VOID SendKeys
(
    _In_ LPWSTR lpString
)
{
    BOOL NeedShift;
    SIZE_T i;
    WORD VkAndShift;

    HKL kl = LoadKeyboardLayout(TEXT("en-US"), KLF_ACTIVATE);

    for (i = 0; i < lstrlenW(lpString); i++) {
        VkAndShift = VkKeyScanEx(lpString[i], kl);
        NeedShift = ((HIBYTE(VkAndShift) & 1) == 1);
        SendControlInput(LOBYTE(VkAndShift), NeedShift, FALSE);
    }
}

BOOL CALLBACK EnumChildCallback
(
    _In_ HWND   hwnd,
    _In_ LPARAM lParam
)
{
    WCHAR wszClassName[0x400];
    WCHAR wszWindowTitle[0x400];

    GetWindowTextW(hwnd, wszWindowTitle, _countof(wszWindowTitle));
    GetClassNameW(hwnd, wszClassName, _countof(wszClassName));
    //if ()
    PrintFormatW(L"----------------------------------------\n");
    PrintFormatW(L"Class name: %s\n", wszClassName);
    PrintFormatW(L"Window name: %s\n", wszWindowTitle);
    return TRUE;
}