#include "pch.h"

// SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA "Win32_Directory" AND TargetInstance.Drive = "C:" AND TargetInstance.Path = "$($Env:TEMP.Substring(2).Replace('\', '\\'))\\" AND TargetInstance.FileName LIKE "________-____-____-____-____________"

BOOL WmiExec
(
	_In_ LPWSTR lpQueryCommand,
	_In_ WMI_QUERY_CALLBACK Callback,
	_In_ LPVOID* Args
)
{
	HRESULT hRes = 0;
	IWbemLocator* pLocator = NULL;
	IWbemServices* pServices = NULL;
	BSTR Resource = SysAllocString(L"ROOT\\CIMV2");
	BSTR Language = SysAllocString(L"WQL");
	BSTR QueryCommand = SysAllocString(lpQueryCommand);
	IEnumWbemClassObject* pResults = NULL;
	IWbemClassObject* pResult = NULL;
	ULONG uReturnedCount = 0;
	BOOL Result = FALSE;
	CLSID CLSID_WbemLocator = { 0x4590F811, 0x1D3A, 0x11D0, { 0x89, 0x1F, 0, 0xAA, 0, 0x4B, 0x2E, 0x24 } };
	IID IID_IWbemLocator = { 0x0DC12A687, 0x737F, 0x11CF, { 0x88, 0x4D, 0, 0xAA, 0, 0x4B, 0x2E, 0x24 } };

	CoInitialize(NULL);
	/*hRes = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, 0);
	if (FAILED(hRes)) {
		goto END;
	}*/

	hRes = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, &pLocator);
	if (FAILED(hRes)) {
		goto END;
	}

	hRes = pLocator->lpVtbl->ConnectServer(pLocator, Resource, NULL, NULL, NULL, 0, NULL, NULL, &pServices);
	if (FAILED(hRes)) {
		goto END;
	}

	hRes = pServices->lpVtbl->ExecQuery(pServices, Language, QueryCommand, WBEM_FLAG_BIDIRECTIONAL, NULL, &pResults);
	if (FAILED(hRes)) {
		goto END;
	}

	while ((hRes = pResults->lpVtbl->Next(pResults, WBEM_INFINITE, 1, &pResult, &uReturnedCount)) == S_OK) {
		/*VARIANT name;
		VARIANT speed;*/

		// obtain the desired properties of the next result and print them out
		/*hResult = pResult->lpVtbl->Get(pResult, L"Name", 0, &name, 0, 0);
		hResult = pResult->lpVtbl->Get(pResult, L"MaxClockSpeed", 0, &speed, 0, 0);*/

		// release the current result object
		if (Callback(pResult, Args)) {
			pResult->lpVtbl->Release(pResult);
			break;
		}

		pResult->lpVtbl->Release(pResult);
	}

	Result = TRUE;
END:
	if (pResults != NULL) {
		pResults->lpVtbl->Release(pResults);
	}

	if (pLocator != NULL) {
		pLocator->lpVtbl->Release(pLocator);
	}

	if (pServices != NULL) {
		pServices->lpVtbl->Release(pServices);
	}

	CoUninitialize();
	return Result;
}

VOID RegisterAsyncEvent
(
	_In_ LPWSTR lpQueryCommand,
	_In_ EVENTSINK_CALLBACK lpCallback,
	_In_ LPVOID Arg
)
{
	HRESULT hResult = 0;
	IWbemLocator* pLocator = NULL;
	IWbemServices* pServices = NULL;
	BSTR Resource = SysAllocString(L"ROOT\\CIMV2");
	BSTR Language = SysAllocString(L"WQL");
	BSTR QueryCommand = SysAllocString(lpQueryCommand);
	IWbemClassObject* pResult = NULL;
	ULONG uReturnedCount = 0;
	IUnsecuredApartment* pUnsecApp = NULL;
	Class_EventSink* pSink = CreateEventSink(lpCallback, Arg);
	IUnknown* pStubUnknown = NULL;
	IWbemObjectSink* pStubSink = NULL;
	HANDLE hEvent = NULL;
	CLSID CLSID_WbemLocator = { 0x4590F811, 0x1D3A, 0x11D0, { 0x89, 0x1F, 0, 0xAA, 0, 0x4B, 0x2E, 0x24 } };
	IID IID_IWbemLocator = { 0x0DC12A687, 0x737F, 0x11CF, { 0x88, 0x4D, 0, 0xAA, 0, 0x4B, 0x2E, 0x24 } };
	IID IID_IWbemObjectSink = { 0x7C857801, 0x7381, 0x11CF, { 0x88, 0x4D, 0, 0xAA, 0, 0x4B, 0x2E, 0x24 } };
	CLSID CLSID_UnsecuredApartment = { 0x49BD2028, 0x1523, 0x11D1, { 0xAD, 0x79, 0, 0xC0, 0x4F, 0xD8, 0xFD, 0xFF } };
	IID IID_IUnsecuredApartment = { 0x1CFABA8C, 0x1523, 0x11D1, { 0xAD, 0x79, 0, 0xC0, 0x4F, 0xD8, 0xFD, 0xFF } };

	CoInitializeEx(0, COINIT_MULTITHREADED);
	/*hResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	if (FAILED(hResult)) {
		LOG_ERROR("CoInitializeSecurity", hResult);
		goto END;
	}*/

	hResult = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, &pLocator);
	if (FAILED(hResult)) {
		LOG_ERROR("CoCreateInstance", hResult);
		goto END;
	}

	hResult = pLocator->lpVtbl->ConnectServer(pLocator, Resource, NULL, NULL, NULL, 0, NULL, NULL, &pServices);
	if (FAILED(hResult)) {
		LOG_ERROR("pLocator->ConnectServer", hResult);
		goto END;
	}

	hResult = CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
	if (FAILED(hResult)) {
		LOG_ERROR("CoSetProxyBlanket", hResult);
		goto END;
	}

	hResult = CoCreateInstance(&CLSID_UnsecuredApartment, NULL, CLSCTX_LOCAL_SERVER, &IID_IUnsecuredApartment, &pUnsecApp);
	if (FAILED(hResult)) {
		LOG_ERROR("CoCreateInstance", hResult);
		goto END;
	}

	EventSink_AddRef(pSink);
	pUnsecApp->lpVtbl->CreateObjectStub(pUnsecApp, pSink, &pStubUnknown);
	pStubUnknown->lpVtbl->QueryInterface(pStubUnknown, &IID_IWbemObjectSink, &pStubSink);
	hResult = pServices->lpVtbl->ExecNotificationQueryAsync(pServices, Language, QueryCommand, WBEM_FLAG_SEND_STATUS, NULL, pStubSink);
	if (FAILED(hResult)) {
		LOG_ERROR("pServices->ExecNotificationQueryAsync", hResult);
		goto END;
	}

	hEvent = CreateEventW(NULL, FALSE, FALSE, L"EventSink");
	WaitForSingleObject(hEvent, INFINITE);
END:
	SysFreeString(Resource);
	SysFreeString(Language);
	SysFreeString(QueryCommand);

	if (pServices != NULL) {
		pServices->lpVtbl->Release(pServices);
	}

	if (pLocator != NULL) {
		pLocator->lpVtbl->Release(pLocator);
	}

	if (pUnsecApp != NULL) {
		pUnsecApp->lpVtbl->Release(pUnsecApp);
	}

	if (pStubUnknown != NULL) {
		pStubUnknown->lpVtbl->Release(pStubUnknown);
	}

	if (pSink != NULL) {
		EventSink_Release(pSink);
	}

	if (pStubSink != NULL) {
		pStubSink->lpVtbl->Release(pStubSink);
	}

	CoUninitialize();
}