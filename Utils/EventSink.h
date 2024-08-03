#pragma once

#define IFACE_GET_PRIVATE(obj, class, private_member)    (((class *)(obj))->private_member)
#define DEFINE_INTERFACE(iface, name, ...)    iface name = {.lpVtbl=&((iface##Vtbl){__VA_ARGS__})}
#define GET_IFACE_CLASS(iface)    Class_##iface

typedef struct _Class_EventSink
{
    IWbemObjectSink;
    LONG m_lRef;
    BOOL bDone;
    EVENTSINK_CALLBACK lpCallback;
    LPVOID Arg;
} Class_EventSink;

VOID WINAPI DestroyEventSink(IWbemObjectSink* this);
ULONG EventSink_Release(IWbemObjectSink* this);
ULONG EventSink_AddRef(IWbemObjectSink* this);
HRESULT EventSink_QueryInterface(IWbemObjectSink* this, REFIID riid, VOID** ppv);
HRESULT EventSink_SetStatus(IWbemObjectSink* this, LONG lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject __RPC_FAR* pObjParam);
HRESULT EventSink_Indicate(IWbemObjectSink* this, long lObjectCount, IWbemClassObject** apObjArray);
IWbemObjectSink* CreateEventSink
(
    _In_ EVENTSINK_CALLBACK lpCallback,
    _In_ LPVOID Arg
);