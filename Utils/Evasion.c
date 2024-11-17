#include "pch.h"

LPVOID GetHeadOfStackTrace() {
	HANDLE hKernel32 = NULL;
	HANDLE hImage = NULL;
	LPVOID lpBaseThreadInitThunk = NULL;
	DWORD cbBaseThreadInitThunk = 0;
	PIMAGE_DOS_HEADER pDosHdr = NULL;
	PIMAGE_NT_HEADERS64 pNtHdr = NULL;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHdr = NULL;
	DWORD dwExceptionDirRva = 0;
	DWORD cbExceptionDir = 0;
	PRUNTIME_FUNCTION pRuntimeFunc = NULL;
	LPVOID lpStartFunc = NULL;
	DWORD i = 0;
	PUINT64 pStackAddr = NULL;
	MEMORY_BASIC_INFORMATION64 MemInfo;
	UINT64 uStackValue = 0;
	LPVOID lpResult = NULL;

	SecureZeroMemory(&MemInfo, sizeof(MemInfo));
	hKernel32 = GetModuleHandleA("kernel32.dll");
	if (hKernel32 == NULL) {
		goto CLEANUP;
	}

	lpBaseThreadInitThunk = GetProcAddress(hKernel32, "BaseThreadInitThunk");
	hImage = GetModuleHandleA(NULL);
	pDosHdr = (PIMAGE_DOS_HEADER)hKernel32;
	pNtHdr = (PIMAGE_NT_HEADERS64)((ULONG_PTR)pDosHdr + pDosHdr->e_lfanew);
	pOptionalHdr = (PIMAGE_FILE_HEADER)&pNtHdr->OptionalHeader;
	dwExceptionDirRva = pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
	cbExceptionDir = pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
	for (i = 0; i < cbExceptionDir; i += sizeof(RUNTIME_FUNCTION)) {
		pRuntimeFunc = (PRUNTIME_FUNCTION)((ULONG_PTR)hKernel32 + dwExceptionDirRva + i);
		lpStartFunc = (LPVOID)((ULONG_PTR)hKernel32 + pRuntimeFunc->BeginAddress);
		if (lpStartFunc == lpBaseThreadInitThunk) {
			cbBaseThreadInitThunk = pRuntimeFunc->EndAddress - pRuntimeFunc->BeginAddress;
			break;
		}
	}

	pStackAddr = (PUINT64)_AddressOfReturnAddress();
	if (VirtualQuery((LPVOID)pStackAddr, &MemInfo, sizeof(MemInfo)) == 0) {
		goto CLEANUP;
	}

	for (i = 0; i < MemInfo.BaseAddress + MemInfo.RegionSize; i += sizeof(UINT64)) {
		uStackValue = *(PUINT64)((ULONG_PTR)pStackAddr + i);
		if (uStackValue > (UINT64)lpBaseThreadInitThunk && uStackValue < (UINT64)lpBaseThreadInitThunk + cbBaseThreadInitThunk) {
			lpResult = (LPVOID)((ULONG_PTR)pStackAddr + i);
			break;
		}
	}

CLEANUP:
	return lpResult;
}

LPVOID StackSpoofing
(
	_In_ LPVOID lpRoutine,
	_In_ DWORD dwNumberOfArguments,
	...
)
{
	UINT64 Stack[0x80];
	va_list Args;
	DWORD i = 0;

	va_start(Args, dwNumberOfArguments);
	for (i = 0; i < dwNumberOfArguments; i++) {
		Stack[i] = va_arg(Args, UINT64);
	}

	va_end(Args);
	return IndirectCall(lpRoutine, Stack);
}