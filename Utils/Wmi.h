#pragma once

VOID RegisterAsyncEvent
(
	_In_ LPWSTR lpQueryCommand,
	_In_ EVENTSINK_CALLBACK lpCallback,
	_In_ LPVOID Arg
);