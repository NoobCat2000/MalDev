#include "pch.h"

typedef HRESULT(WINAPI* CLRCREATEINSTANCE)(REFCLSID, REFIID, LPVOID*);

LPSTR* GetRuntimeVersion
(
	_Out_ PDWORD pdwNumberOfRuntimes
)
{
	HMODULE hMscoree = NULL;
	LPSTR* pResult = NULL;
	CLRCREATEINSTANCE fnCLRCreateInstance = NULL;
	HRESULT ReturnCode = S_OK;
	ICLRMetaHost* pCLRMetaHost = NULL;
	IEnumUnknown* IEnum = NULL;
	ICLRRuntimeInfo* IRuntimeInfo = NULL;
	LPWSTR wszVersion[0x200];
	DWORD cchVersion = 0;
	IUnknown* IEnumRuntime = NULL;
	DWORD dwNumberOfRuntimes = 0;
	CLSID CLSID_CLRMetaHost = { 0x9280188D, 0xE8E, 0x4867, { 0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE } };
	IID IID_ICLRMetaHost = { 0x0D332DB9E, 0x0B9B3, 0x4125, { 0x82, 7, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } };
	IID IID_ICLRRuntimeInfo = { 0xBD39D1D2, 0xBA2F, 0x486A, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } };

	hMscoree = LoadLibraryW(L"mscoree.dll");
	if (hMscoree == NULL) {
		LOG_ERROR("LoadLibraryW", GetLastError());
		goto CLEANUP;
	}

	fnCLRCreateInstance = (CLRCREATEINSTANCE)GetProcAddress(hMscoree, "CLRCreateInstance");
	if (fnCLRCreateInstance == NULL) {
		LOG_ERROR("GetProcAddress", GetLastError());
		goto CLEANUP;
	}

	ReturnCode = fnCLRCreateInstance(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, (LPVOID*)(&pCLRMetaHost));
	if (!SUCCEEDED(ReturnCode)) {
		LOG_ERROR("CLRCreateInstance", ReturnCode);
		if (ReturnCode == E_NOTIMPL) {

		}

		goto CLEANUP;
	}

	ReturnCode = pCLRMetaHost->lpVtbl->EnumerateInstalledRuntimes(pCLRMetaHost, &IEnum);
	if (!SUCCEEDED(ReturnCode)) {
		LOG_ERROR("pCLRMetaHost->EnumerateInstalledRuntimes", ReturnCode);
		goto CLEANUP;
	}

	while (IEnum->lpVtbl->Next(IEnum, 1, &IEnumRuntime, NULL) == S_OK) {
		ReturnCode = IEnumRuntime->lpVtbl->QueryInterface(IEnumRuntime, &IID_ICLRRuntimeInfo, &IRuntimeInfo);
		if (!SUCCEEDED(ReturnCode)) {
			LOG_ERROR("IEnumRuntime->QueryInterface", ReturnCode);
			goto CLEANUP;
		}

		SecureZeroMemory(wszVersion, sizeof(wszVersion));
		cchVersion = _countof(wszVersion);
		ReturnCode = IRuntimeInfo->lpVtbl->GetVersionString(IRuntimeInfo, wszVersion, &cchVersion);
		if (!SUCCEEDED(ReturnCode)) {
			LOG_ERROR("IRuntimeInfo->GetVersionString", ReturnCode);
			goto CLEANUP;
		}

		if (pResult == NULL) {
			pResult = ALLOC(sizeof(LPSTR));
		}
		else {
			pResult = REALLOC(pResult, sizeof(LPSTR) * (dwNumberOfRuntimes));
		}

		pResult[dwNumberOfRuntimes++] = ConvertWcharToChar(wszVersion);
		IRuntimeInfo->lpVtbl->Release(IRuntimeInfo);
	}

	if (pdwNumberOfRuntimes != NULL) {
		*pdwNumberOfRuntimes = dwNumberOfRuntimes;
	}

CLEANUP:
	if (IRuntimeInfo != NULL) {
		IRuntimeInfo->lpVtbl->Release(IRuntimeInfo);
	}

	if (IEnum != NULL) {
		IEnum->lpVtbl->Release(IEnum);
	}

	if (pCLRMetaHost != NULL) {
		pCLRMetaHost->lpVtbl->Release(pCLRMetaHost);
	}

	return pResult;
}