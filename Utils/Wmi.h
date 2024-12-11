#pragma once

typedef BOOL(WINAPI* WMI_QUERY_CALLBACK)(IWbemClassObject*, LPVOID*);

VOID RegisterAsyncEvent
(
	_In_ LPWSTR lpQueryCommand,
	_In_ EVENTSINK_CALLBACK lpCallback,
	_In_ LPVOID Arg
);

BOOL WmiExec
(
	_In_ LPWSTR lpQueryCommand,
	_In_ WMI_QUERY_CALLBACK Callback,
	_In_ LPVOID* Args
);