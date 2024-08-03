#include "pch.h"

VOID WINAPI DestroyEventSink(IWbemObjectSink* this) {
	FREE(this);
}

IWbemObjectSink* CreateEventSink
(
	_In_ EVENTSINK_CALLBACK lpCallback,
	_In_ LPVOID Arg
)
{
	Class_EventSink* p = ALLOC(sizeof(Class_EventSink));
	if (!p) {
		return NULL;
	}

	IWbemObjectSinkVtbl* pSinkVtbl = ALLOC(sizeof(IWbemObjectSinkVtbl));
	pSinkVtbl->AddRef = EventSink_AddRef;
	pSinkVtbl->QueryInterface = EventSink_QueryInterface;
	pSinkVtbl->Release = EventSink_Release;
	pSinkVtbl->Indicate = EventSink_Indicate;
	pSinkVtbl->SetStatus = EventSink_SetStatus;

	p->m_lRef = 0;
	p->bDone = FALSE;
	p->lpVtbl = pSinkVtbl;
	p->lpCallback = lpCallback;
	p->Arg = Arg;

	return (IWbemObjectSink*)p;
}

ULONG EventSink_Release(IWbemObjectSink* this) {
	LONG lRef = InterlockedDecrement(&(IFACE_GET_PRIVATE(this, Class_EventSink, m_lRef)));
	if (lRef == 0)
	{
		DestroyEventSink(this);
	}

	return lRef;
}

ULONG EventSink_AddRef(IWbemObjectSink* this) {
	return InterlockedIncrement(&(IFACE_GET_PRIVATE(this, Class_EventSink, m_lRef)));
}

HRESULT EventSink_QueryInterface(IWbemObjectSink* this, REFIID riid, void** ppv) {
	if (IsEqualCLSID(riid, &IID_IUnknown) || IsEqualCLSID(riid, &IID_IWbemObjectSink)) {
		*ppv = (IWbemObjectSink*)this;
		EventSink_AddRef(this);
		return WBEM_S_NO_ERROR;
	}
	else {
		return E_NOINTERFACE;
	}
}

HRESULT EventSink_SetStatus(IWbemObjectSink* this, LONG lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject __RPC_FAR* pObjParam) {
	return WBEM_S_NO_ERROR;
}

HRESULT EventSink_Indicate(IWbemObjectSink* this, long lObjectCount, IWbemClassObject** apObjArray) {
	UINT32 i = 0;
	BSTR strObjectText;
	HANDLE hEvent = NULL;

	Class_EventSink* EventSinkInst = (Class_EventSink*)this;
	for (i = 0; i < lObjectCount; i++) {
		apObjArray[i]->lpVtbl->GetObjectText(apObjArray[i], 0, &strObjectText);
		EventSinkInst->lpCallback(strObjectText, EventSinkInst->Arg);
	}

	hEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, L"EventSink");
	SetEvent(hEvent);
	CloseHandle(hEvent);
	return WBEM_S_NO_ERROR;
}