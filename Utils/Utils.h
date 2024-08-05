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