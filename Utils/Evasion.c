#include "pch.h"

UINT64 GetHeadOfStack()
{
	HANDLE hKernel32 = NULL;
	LPVOID lpBaseThreadInitThunk = NULL;
	PIMAGE_DOS_HEADER pDosHdr = NULL;
	PIMAGE_NT_HEADERS64 pNtHdr = NULL;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHdr = NULL;
	DWORD dwExceptionDirRva = 0;
	DWORD cbExceptionDir = 0;
	PRUNTIME_FUNCTION pRuntimeFunc = NULL;
	UINT64 uBaseThreadInitThunkStart = 0;
	UINT64 uBaseThreadInitThunkEnd = 0;
	DWORD i = 0;
	PUINT64 pStackAddr = NULL;
	MEMORY_BASIC_INFORMATION64 MemInfo;
	UINT64 uStackValue = 0;
	UINT64 uResult = 0;

	SecureZeroMemory(&MemInfo, sizeof(MemInfo));
	hKernel32 = GetModuleHandleA("kernel32.dll");
	if (hKernel32 == NULL) {
		goto CLEANUP;
	}

	lpBaseThreadInitThunk = GetProcAddress(hKernel32, "BaseThreadInitThunk");
	pDosHdr = (PIMAGE_DOS_HEADER)hKernel32;
	pNtHdr = (PIMAGE_NT_HEADERS64)((ULONG_PTR)pDosHdr + pDosHdr->e_lfanew);
	pOptionalHdr = (PIMAGE_FILE_HEADER)&pNtHdr->OptionalHeader;
	dwExceptionDirRva = pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
	cbExceptionDir = pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
	for (i = 0; i < cbExceptionDir; i += sizeof(RUNTIME_FUNCTION)) {
		pRuntimeFunc = (PRUNTIME_FUNCTION)((ULONG_PTR)hKernel32 + dwExceptionDirRva + i);
		uBaseThreadInitThunkStart = (UINT64)hKernel32 + pRuntimeFunc->BeginAddress;
		if (uBaseThreadInitThunkStart == (UINT64)lpBaseThreadInitThunk) {
			uBaseThreadInitThunkEnd = (UINT64)hKernel32 + pRuntimeFunc->EndAddress;
			break;
		}
	}

	pStackAddr = (PUINT64)_AddressOfReturnAddress();
	if (VirtualQuery((LPVOID)pStackAddr, &MemInfo, sizeof(MemInfo)) == 0) {
		goto CLEANUP;
	}

	for (i = 0; i < MemInfo.BaseAddress + MemInfo.RegionSize; i += sizeof(UINT64)) {
		uStackValue = *(PUINT64)((UINT64)pStackAddr + i);
		if (uStackValue > uBaseThreadInitThunkStart && uStackValue < uBaseThreadInitThunkEnd) {
			uResult = (UINT64)pStackAddr + i;
			break;
		}
	}

CLEANUP:
	return uResult;
}

DWORD GetStackFrameSize
(
	_In_ HMODULE hModule,
	_In_ PUNWIND_INFO pUnwindInfo
)
{
    PRUNTIME_FUNCTION pChainedFunction;
    DWORD dwFrameSize = 0;
    DWORD i = 0;
    PUNWIND_CODE pUnwindCode = NULL;
	DWORD dwResult = 0;

	pUnwindCode = pUnwindInfo->UnwindCode;
    while (i < pUnwindInfo->CountOfCodes) {
		dwFrameSize = 0;
		if (pUnwindCode->UnwindOp == UWOP_PUSH_NONVOL) {
			dwResult += 8;
		}
		else if (pUnwindCode->UnwindOp == UWOP_ALLOC_LARGE) {
			pUnwindCode = &pUnwindCode[1];
			i++;
			if (pUnwindCode->OpInfo == 0) {
				dwFrameSize += pUnwindCode->FrameOffset * 8;
			}
			else {
				dwFrameSize += *((PDWORD)(pUnwindCode));
				i++;
			}

			dwResult += dwFrameSize;
		}
		else if (pUnwindCode->UnwindOp == UWOP_ALLOC_SMALL) {
			dwResult += 8 * (pUnwindCode->OpInfo + 1);
		}
		else if (pUnwindCode->UnwindOp == UWOP_SET_FPREG) {
			
		}
		else if (pUnwindCode->UnwindOp == UWOP_SAVE_NONVOL) {
			pUnwindCode = &pUnwindCode[1];
			i++;
		}
		else if (pUnwindCode->UnwindOp == UWOP_SAVE_NONVOL_BIG) {
			pUnwindCode = &pUnwindCode[2];
			i += 2;
		}
		else if (pUnwindCode->UnwindOp == UWOP_EPILOG || pUnwindCode->UnwindOp == UWOP_SAVE_XMM128) {
			pUnwindCode = &pUnwindCode[1];
			i++;
		}
		else if (pUnwindCode->UnwindOp == UWOP_SPARE_CODE || pUnwindCode->UnwindOp == UWOP_SAVE_XMM128BIG) {
			pUnwindCode = &pUnwindCode[2];
			i += 2;
		}
		else if (pUnwindCode->UnwindOp == UWOP_PUSH_MACH_FRAME) {
			if (pUnwindCode->OpInfo == 0) {
				dwResult += 0x40;
			}
			else {
				dwResult += 0x48;
            }
        }

		pUnwindCode = &pUnwindCode[1];
        i++;
    }

	if ((pUnwindInfo->Flags & UNW_FLAG_CHAININFO) == UNW_FLAG_CHAININFO) {
        pChainedFunction = (PRUNTIME_FUNCTION)&(pUnwindInfo->UnwindCode[(pUnwindInfo->CountOfCodes + 1) & ~1]);
		dwResult += GetStackFrameSize(hModule, (PUNWIND_INFO)((UINT64)hModule + (DWORD)pChainedFunction->UnwindData));
    }

    return dwResult;
}

UINT64 FindGadget
(
	_In_ DWORD dwGadgetType,
	_Out_ PDWORD pcbStackFrame
)
{
	HMODULE* ModuleList = NULL;
	DWORD cbModuleList = 0;
	DWORD cbNeeded = 0;
	UINT64 uResult = 0;
	DWORD i = 0;
	DWORD j = 0;
	PRUNTIME_FUNCTION pRuntimeFunctionList = NULL;
	DWORD dwNumberOfFunctions = 0;
	PBYTE pFunctionStart = NULL;
	PBYTE pFunctionEnd = NULL;
	PBYTE pPosition = NULL;
	HMODULE hMainModule = NULL;
	PUNWIND_INFO pUnwindInfo = NULL;
	CHAR szModuleFileName[MAX_PATH];

	hMainModule = GetModuleHandleA(NULL);
	cbModuleList = sizeof(HMODULE) * 100;
	ModuleList = ALLOC(cbModuleList);
	while (TRUE) {
		cbNeeded = 0;
		if (!K32EnumProcessModules(GetCurrentProcess(), ModuleList, cbModuleList, &cbNeeded)) {
			goto CLEANUP;
		}

		if (cbModuleList == cbNeeded) {
			break;
		}

		cbModuleList = cbNeeded;
		ModuleList = REALLOC(ModuleList, cbModuleList);
	}

	for (i = 0; i < cbModuleList / sizeof(HMODULE); i++) {
		if (hMainModule == ModuleList[i]) {
			continue;
		}

		GetModuleFileNameA(ModuleList[i], szModuleFileName, _countof(szModuleFileName));
		if (!StrStrA(szModuleFileName, "System32") || (!StrStrA(szModuleFileName, ".dll") && !StrStrA(szModuleFileName, ".DLL"))) {
			continue;
		}

		pRuntimeFunctionList = GetExceptionDirectoryAddress(ModuleList[i], &dwNumberOfFunctions);
		for (j = 0; j < dwNumberOfFunctions; j++) {
			pFunctionStart = (PBYTE)((UINT64)ModuleList[i] + pRuntimeFunctionList[j].BeginAddress);
			pFunctionEnd = (PBYTE)((UINT64)ModuleList[i] + pRuntimeFunctionList[j].EndAddress);
			if (dwGadgetType == 0) {
				pPosition = pFunctionEnd - 5;
				if (pPosition[0] == 0x48 && pPosition[1] == 0x83 && pPosition[2] == 0xc4 && pPosition[4] == 0xc3) {
					if ((pPosition[3] >> 4) > 6 && (pPosition[3] & 0xF) == 8) {
						uResult = (UINT64)pPosition;
						if (pcbStackFrame != NULL) {
							*pcbStackFrame = pPosition[3];
						}

						goto CLEANUP;
					}
				}
			}
			else if (dwGadgetType == 1) {
				for (pPosition = pFunctionStart; pPosition < pFunctionEnd; pPosition++) {
					if (pPosition[0] == 0xff && pPosition[1] == 0x23) {
						uResult = (UINT64)pPosition;
						if (pcbStackFrame != NULL) {
							pUnwindInfo = (PUNWIND_INFO)((UINT64)ModuleList[i] + pRuntimeFunctionList[j].UnwindInfoAddress);
							*pcbStackFrame = GetStackFrameSize(ModuleList[i], pUnwindInfo);
						}

						goto CLEANUP;
					}
				}
			}
			else {
				goto CLEANUP;
			}
		}
	}

CLEANUP:
	FREE(ModuleList);
	return uResult;
}

UINT64 FindSetFpProlog
(
	_Out_ PDWORD pdwFrameOffset,
	_Out_ PDWORD pdwFrameSize,
	_Out_ PDWORD pdwRandomOffset
)
{
	HMODULE* ModuleList = NULL;
	DWORD cbModuleList = 0;
	DWORD cbNeeded = 0;
	UINT64 uResult = 0;
	DWORD i = 0;
	DWORD j = 0;
	PRUNTIME_FUNCTION pRuntimeFunctionList = NULL;
	DWORD dwNumberOfFunctions = 0;
	PBYTE pFunctionStart = NULL;
	PBYTE pFunctionEnd = NULL;
	PBYTE pPosition = NULL;
	HMODULE hMainModule = NULL;
	PUNWIND_INFO pUnwindInfo = NULL;
	CHAR szModuleFileName[MAX_PATH];
	PUNWIND_CODE pUnwindCode = NULL;
	DWORD dwFunctionSize = 0;

	hMainModule = GetModuleHandleA(NULL);
	cbModuleList = sizeof(HMODULE) * 100;
	ModuleList = ALLOC(cbModuleList);
	while (TRUE) {
		cbNeeded = 0;
		if (!K32EnumProcessModules(GetCurrentProcess(), ModuleList, cbModuleList, &cbNeeded)) {
			goto CLEANUP;
		}

		if (cbModuleList == cbNeeded) {
			break;
		}

		cbModuleList = cbNeeded;
		ModuleList = REALLOC(ModuleList, cbModuleList);
	}

	for (i = 0; i < cbModuleList / sizeof(HMODULE); i++) {
		if (hMainModule == ModuleList[i]) {
			continue;
		}

		GetModuleFileNameA(ModuleList[i], szModuleFileName, _countof(szModuleFileName));
		if (!StrStrA(szModuleFileName, "System32") || (!StrStrA(szModuleFileName, ".dll") && !StrStrA(szModuleFileName, ".DLL"))) {
			continue;
		}

		pRuntimeFunctionList = GetExceptionDirectoryAddress(ModuleList[i], &dwNumberOfFunctions);
		for (j = 0; j < dwNumberOfFunctions; j++) {
			pFunctionStart = (PBYTE)((UINT64)ModuleList[i] + pRuntimeFunctionList[j].BeginAddress);
			pFunctionEnd = (PBYTE)((UINT64)ModuleList[i] + pRuntimeFunctionList[j].EndAddress);
			pUnwindInfo = (PUNWIND_INFO)((UINT64)ModuleList[i] + pRuntimeFunctionList[j].UnwindInfoAddress);
			if (pUnwindInfo->FrameRegister == RBP) {
				if (pdwFrameOffset != NULL) {
					*pdwFrameOffset = 0x10 * pUnwindInfo->FrameOffset;
				}

				if (pdwFrameSize != NULL) {
					*pdwFrameSize = GetStackFrameSize(ModuleList[i], pUnwindInfo);
				}

				if (pdwRandomOffset != NULL) {
					dwFunctionSize = (DWORD)((UINT64)pFunctionEnd - (UINT64)pFunctionStart);
					*pdwRandomOffset = GenRandomNumber32(pUnwindInfo->SizeOfProlog, dwFunctionSize);
				}

				uResult = (UINT64)pFunctionStart;
				goto CLEANUP;
			}
			
		}
	}

CLEANUP:
	FREE(ModuleList);
	return uResult;
}

UINT64 FindSaveRbp
(
	_Out_ PDWORD pdwFrameOffset,
	_Out_ PDWORD pdwFrameSize,
	_Out_ PDWORD pdwRandomOffset
)
{
	HMODULE* ModuleList = NULL;
	DWORD cbModuleList = 0;
	DWORD cbNeeded = 0;
	UINT64 uResult = 0;
	DWORD i = 0;
	DWORD j = 0;
	DWORD k = 0;
	PRUNTIME_FUNCTION pRuntimeFunctionList = NULL;
	DWORD dwNumberOfFunctions = 0;
	HMODULE hMainModule = NULL;
	PUNWIND_INFO pUnwindInfo = NULL;
	CHAR szModuleFileName[MAX_PATH];
	PUNWIND_CODE pUnwindCode = NULL;
	DWORD dwStackOffset = 0;
	DWORD dwFunctionSize = 0;

	if (pdwFrameOffset == NULL) {
		return 0;
	}

	*pdwFrameOffset = 0;
	hMainModule = GetModuleHandleA(NULL);
	cbModuleList = sizeof(HMODULE) * 100;
	ModuleList = ALLOC(cbModuleList);
	while (TRUE) {
		cbNeeded = 0;
		if (!K32EnumProcessModules(GetCurrentProcess(), ModuleList, cbModuleList, &cbNeeded)) {
			goto CLEANUP;
		}

		if (cbModuleList == cbNeeded) {
			break;
		}

		cbModuleList = cbNeeded;
		ModuleList = REALLOC(ModuleList, cbModuleList);
	}

	for (i = 0; i < cbModuleList / sizeof(HMODULE); i++) {
		if (hMainModule == ModuleList[i]) {
			continue;
		}

		GetModuleFileNameA(ModuleList[i], szModuleFileName, _countof(szModuleFileName));
		if (!StrStrA(szModuleFileName, "System32") || (!StrStrA(szModuleFileName, ".dll") && !StrStrA(szModuleFileName, ".DLL"))) {
			continue;
		}

		pRuntimeFunctionList = GetExceptionDirectoryAddress(ModuleList[i], &dwNumberOfFunctions);
		for (j = 0; j < dwNumberOfFunctions; j++) {
			pUnwindInfo = (PUNWIND_INFO)((UINT64)ModuleList[i] + pRuntimeFunctionList[j].UnwindInfoAddress);
			dwStackOffset = 0;
			for (k = 0; k < pUnwindInfo->CountOfCodes; k++) {
				pUnwindCode = &pUnwindInfo->UnwindCode[k];
				if (pUnwindCode->UnwindOp == UWOP_ALLOC_LARGE) {
					k++;
					pUnwindCode = &pUnwindInfo->UnwindCode[k];
					if (pUnwindCode->OpInfo == 1) {
						dwStackOffset += *((PDWORD)(pUnwindCode));
						k++;
					}
					else if (pUnwindCode->OpInfo == 0) {
						dwStackOffset += 8 * pUnwindCode->FrameOffset;
					}
				}
				else if (pUnwindCode->UnwindOp == UWOP_ALLOC_SMALL) {
					dwStackOffset += 8 * (pUnwindCode->OpInfo + 1);
				}
				else if (pUnwindCode->UnwindOp == UWOP_SAVE_NONVOL) {
					k++;
					if (pUnwindCode->OpInfo == RBP) {
						*pdwFrameOffset = pUnwindInfo->UnwindCode[k].FrameOffset * 8;
					}
				}
				else if (pUnwindCode->UnwindOp == UWOP_EPILOG || pUnwindCode->UnwindOp == UWOP_SAVE_XMM128) {
					k++;
				}
				else if (pUnwindCode->UnwindOp == UWOP_SAVE_NONVOL_BIG) {
					if (pUnwindCode->OpInfo == RBP) {
						*pdwFrameOffset = *((PWORD)(&pUnwindInfo->UnwindCode[k + 1]));
					}

					k += 2;
				}
				else if (pUnwindCode->UnwindOp == UWOP_SPARE_CODE || pUnwindCode->UnwindOp == UWOP_SAVE_XMM128BIG) {
					k += 2;
				}
				else if (pUnwindCode->UnwindOp == UWOP_PUSH_NONVOL) {
					if (pUnwindCode->OpInfo == RBP) {
						*pdwFrameOffset = dwStackOffset;
					}

					dwStackOffset += 8;
				}
				else if (pUnwindCode->UnwindOp == UWOP_PUSH_MACH_FRAME) {
					if (pUnwindCode->OpInfo == 0) {
						dwStackOffset += 0x40;
					}
					else {
						dwStackOffset += 0x48;
					}
				}
			}

			if (*pdwFrameOffset > 0) {
				uResult = (UINT64)ModuleList[i] + pRuntimeFunctionList[j].BeginAddress;
				if (pdwFrameSize != NULL) {
					*pdwFrameSize = dwStackOffset;
				}

				if (pdwRandomOffset != NULL) {
					dwFunctionSize = pRuntimeFunctionList[j].EndAddress - pRuntimeFunctionList[j].BeginAddress;
					*pdwRandomOffset = GenRandomNumber32(pUnwindInfo->SizeOfProlog, dwFunctionSize);
				}

				goto CLEANUP;
			}
		}
	}

CLEANUP:
	FREE(ModuleList);
	return uResult;
}

BOOL SetupStackSpoofing(void)
{
	BOOL Result = FALSE;
	UINT64 uSavedRbp = 0;
	DWORD dwSaveRbpOffset = 0;
	DWORD dwSaveRbpFrameSize = 0;
	DWORD dwSaveRbpFrameOffset = 0;
	UINT64 uSetFP = 0;
	DWORD dwSetFPOffset = 0;
	DWORD dwSetFPFrameSize = 0;
	DWORD dwSetFPFrameOffset = 0;
	UINT64 uBaseThreadInitThunkStackAddress = 0;
	UINT64 uJmpRbxGadget = 0;
	DWORD dwJmpRbxFrameSize = 0;
	UINT64 uAddRspGadget = 0;
	DWORD dwAddRspFrameSize = 0;
	PBYTE pSpoofCallAddr = NULL;
	DWORD i = 0;
	DWORD dwCounter = 0;

	uSavedRbp = FindSaveRbp(&dwSaveRbpFrameOffset, &dwSaveRbpFrameSize, &dwSaveRbpOffset);
	if (uSavedRbp == 0) {
		goto CLEANUP;
	}

	uSetFP = FindSetFpProlog(&dwSetFPFrameOffset, &dwSetFPFrameSize, &dwSetFPOffset);
	if (uSetFP == 0) {
		goto CLEANUP;
	}

	uBaseThreadInitThunkStackAddress = GetHeadOfStack();
	if (uBaseThreadInitThunkStackAddress == 0) {
		goto CLEANUP;
	}

	uJmpRbxGadget = FindGadget(1, &dwJmpRbxFrameSize);
	if (uJmpRbxGadget == 0) {
		goto CLEANUP;
	}

	uAddRspGadget = FindGadget(0, &dwAddRspFrameSize);
	if (dwAddRspFrameSize == 0) {
		goto CLEANUP;
	}

	pSpoofCallAddr = (PBYTE)SpoofCall;
	for (i = 0; i < 0x100; i++) {
		if (!memcmp(&pSpoofCallAddr[i], "\x88\x77\x66\x55\x44\x33\x22\x11", 8)) {
			if (dwCounter == 0) {
				*((PUINT64)(&pSpoofCallAddr[i])) = uSetFP;
			}
			else if (dwCounter == 1) {
				*((PUINT64)(&pSpoofCallAddr[i])) = uSavedRbp;
			}
			else if (dwCounter == 2) {
				*((PUINT64)(&pSpoofCallAddr[i])) = uJmpRbxGadget;
			}
			else if (dwCounter == 3) {
				*((PUINT64)(&pSpoofCallAddr[i])) = uAddRspGadget;
			}
			else if (dwCounter == 4) {
				*((PUINT64)(&pSpoofCallAddr[i])) = dwSetFPFrameSize;
			}
			else if (dwCounter == 5) {
				*((PUINT64)(&pSpoofCallAddr[i])) = dwSetFPOffset;
			}
			else if (dwCounter == 6) {
				*((PUINT64)(&pSpoofCallAddr[i])) = dwSaveRbpFrameSize;
			}
			else if (dwCounter == 7) {
				*((PUINT64)(&pSpoofCallAddr[i])) = dwSaveRbpOffset;
			}
			else if (dwCounter == 8) {
				*((PUINT64)(&pSpoofCallAddr[i])) = dwJmpRbxFrameSize;
			}
			else if (dwCounter == 9) {
				*((PUINT64)(&pSpoofCallAddr[i])) = dwAddRspFrameSize;
			}
			else if (dwCounter == 10) {
				*((PUINT64)(&pSpoofCallAddr[i])) = dwSaveRbpFrameOffset;
			}
			else if (dwCounter == 11) {
				*((PUINT64)(&pSpoofCallAddr[i])) = uBaseThreadInitThunkStackAddress;
			}
			else if (dwCounter == 12) {
				*((PUINT64)(&pSpoofCallAddr[i])) = dwSetFPFrameOffset;
				break;
			}

			dwCounter++;
			i += 7;
		}
	}

	Result = TRUE;
CLEANUP:
	return Result;
}