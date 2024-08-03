#include "pch.h"

// SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA "Win32_Directory" AND TargetInstance.Drive = "C:" AND TargetInstance.Path = "$($Env:TEMP.Substring(2).Replace('\', '\\'))\\" AND TargetInstance.FileName LIKE "________-____-____-____-____________"

VOID WmiExec
(
	_In_ LPWSTR lpQueryCommand
)
{
	HRESULT hResult = 0;
	IWbemLocator* pLocator = NULL;
	IWbemServices* pServices = NULL;
	BSTR Resource = SysAllocString(L"ROOT\\CIMV2");
	BSTR Language = SysAllocString(L"WQL");
	BSTR QueryCommand = SysAllocString(lpQueryCommand);
	IEnumWbemClassObject* pResults = NULL;
	IWbemClassObject* pResult = NULL;
	ULONG uReturnedCount = 0;
	// 4590f811-1d3a-11d0-891f-00aa004b2e24
	hResult = CoInitialize(NULL);
	if (FAILED(hResult)) {
		goto END;
	}

	hResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, 0);
	if (FAILED(hResult)) {
		goto END;
	}

	hResult = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, &pLocator);
	if (FAILED(hResult)) {
		goto END;
	}

	hResult = pLocator->lpVtbl->ConnectServer(pLocator, Resource, NULL, NULL, NULL, 0, NULL, NULL, &pServices);
	if (FAILED(hResult)) {
		goto END;
	}

	hResult = pServices->lpVtbl->ExecQuery(pServices, Language, QueryCommand, WBEM_FLAG_BIDIRECTIONAL, NULL, &pResults);
	if (FAILED(hResult)) {
		goto END;
	}

	while ((hResult = pResults->lpVtbl->Next(pResults, WBEM_INFINITE, 1, &pResult, &uReturnedCount)) == S_OK) {
		/*VARIANT name;
		VARIANT speed;*/

		// obtain the desired properties of the next result and print them out
		/*hResult = pResult->lpVtbl->Get(pResult, L"Name", 0, &name, 0, 0);
		hResult = pResult->lpVtbl->Get(pResult, L"MaxClockSpeed", 0, &speed, 0, 0);*/
		//wprintf(L"%s, %dMHz\r\n", name.bstrVal, speed.intVal);

		// release the current result object
		pResult->lpVtbl->Release(pResult);
	}
END:
	if (pServices != NULL) {
		pServices->lpVtbl->Release(pServices);
	}

	if (pLocator != NULL) {
		pLocator->lpVtbl->Release(pLocator);
	}

	if (pResults != NULL) {
		pResults->lpVtbl->Release(pResults);
	}

	CoUninitialize();
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

	hResult = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hResult)) {
		wprintf(L"CoInitializeEx failed: 0x%08x\n", hResult);
		goto END;
	}

	hResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	if (FAILED(hResult)) {
		wprintf(L"CoInitializeSecurity failed: 0x%08x\n", hResult);
		goto END;
	}

	hResult = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, &pLocator);
	if (FAILED(hResult)) {
		wprintf(L"CoCreateInstance(&CLSID_WbemLocator) failed: 0x%08x\n", hResult);
		goto END;
	}

	hResult = pLocator->lpVtbl->ConnectServer(pLocator, Resource, NULL, NULL, 0, NULL, 0, 0, &pServices);
	if (FAILED(hResult)) {
		wprintf(L"ConnectServer failed: 0x%08x\n", hResult);
		goto END;
	}

	hResult = CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
	if (FAILED(hResult)) {
		wprintf(L"CoSetProxyBlanket failed: 0x%08x\n", hResult);
		goto END;
	}

	hResult = CoCreateInstance(&CLSID_UnsecuredApartment, NULL, CLSCTX_LOCAL_SERVER, &IID_IUnsecuredApartment, &pUnsecApp);
	if (FAILED(hResult)) {
		wprintf(L"CoCreateInstance(&CLSID_UnsecuredApartment) failed: 0x%08x\n", hResult);
		goto END;
	}

	EventSink_AddRef(pSink);
	pUnsecApp->lpVtbl->CreateObjectStub(pUnsecApp, pSink, &pStubUnknown);
	pStubUnknown->lpVtbl->QueryInterface(pStubUnknown, &IID_IWbemObjectSink, &pStubSink);
	hResult = pServices->lpVtbl->ExecNotificationQueryAsync(pServices, Language, QueryCommand, WBEM_FLAG_SEND_STATUS, NULL, pStubSink);
	if (FAILED(hResult)) {
		wprintf(L"ExecNotificationQueryAsync failed: 0x%08x\n", hResult);
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