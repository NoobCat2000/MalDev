#pragma once

LPVOID IndirectCall(LPVOID lpRoutine, PUINT64 pParentStack);

LPVOID StackSpoofing
(
	_In_ LPVOID lpRoutine,
	_In_ DWORD dwNumberOfArguments,
	...
);