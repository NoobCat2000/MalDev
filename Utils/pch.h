// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

#include <WinSock2.h>
#include <ws2ipdef.h>
#include <phnt_windows.h>
#include <phnt.h>
#include <strsafe.h>
#include <Shlwapi.h>
#include <wincrypt.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <combaseapi.h>
#include <Wbemidl.h>
#include <Wbemcli.h>
#include <shlobj_core.h>
#include <MSTask.h>
#include <taskschd.h>
#include <WtsApi32.h>
#include <sddl.h>
#include <WinTrust.h>
#include <compressapi.h>
#include <Lmcons.h>
#include <dbghelp.h>
#include <iphlpapi.h>
#include <AclAPI.h>
#include <shobjidl.h>
#include <windns.h>
#include <stdio.h>
#include <intrin.h>
#include <mscoree.h>
#include <metahost.h>
#include <Propvarutil.h>

#include "framework.h"
#include "Utils.h"
#include "EventSink.h"

#endif //PCH_H

//static HMODULE GetModuleHandleH(DWORD ModuleHash) {
//	PPEB pPeb = (PPEB)__readgsqword(0x60);
//	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
//	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
//	WCHAR Temp = L'\0';
//
//	while (pDte) {
//		if (pDte->FullDllName.Buffer != NULL) {
//			if (pDte->FullDllName.Length < MAX_PATH - 1) {
//				CHAR DllName[MAX_PATH] = { 0 };
//				DWORD i = 0;
//				while (pDte->FullDllName.Buffer[i] && i < sizeof(DllName) - 1) {
//					Temp = pDte->FullDllName.Buffer[i];
//					if (Temp >= L'a' && Temp <= L'z') {
//						DllName[i] = Temp - L'a' + L'A';
//					}
//					else {
//						DllName[i] = Temp;
//					}
//
//					i++;
//				}
//				DllName[i] = '\0';
//				if (HASHA(DllName) == ModuleHash) {
//					return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
//				}
//			}
//		}
//		else {
//			break;
//		}
//
//		pDte = (PLDR_DATA_TABLE_ENTRY)(*(PUINT64)(pDte));
//	}
//	return NULL;
//}
//
//static FARPROC GetProcAddressH
//(
//	DWORD moduleHash,
//	DWORD dwHash
//)
//{
//	HMODULE hModule = NULL;
//	PIMAGE_DOS_HEADER pDosHdr = NULL;
//	PIMAGE_NT_HEADERS64 pNtHdr = NULL;
//	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
//	DWORD i = 0;
//	DWORD j = 0;
//	PDWORD pAddressTable = NULL;
//	PDWORD pNameTable = NULL;
//	PWORD pNameOrdTable = NULL;
//	UINT64 DllBaseAddress = 0;
//	LPSTR lpFunctionName = NULL;
//	PIMAGE_SECTION_HEADER pTextSection = NULL;
//	DWORD dwNumberOfSections = 0;
//	DWORD dwFunctionRVA = 0;
//	FARPROC pResult = NULL;
//	CHAR szDllName[0x40];
//	LPSTR lpProcInfo = NULL;
//
//	if (pResult != NULL) {
//		return pResult;
//	}
//
//	hModule = GetModuleHandleH(moduleHash);
//	if (hModule == NULL) {
//		return NULL;
//	}
//
//	DllBaseAddress = (UINT64)hModule;
//	pNtHdr = (PIMAGE_NT_HEADERS64)(DllBaseAddress + ((PIMAGE_DOS_HEADER)DllBaseAddress)->e_lfanew);
//	pExportDir = (PIMAGE_EXPORT_DIRECTORY)(DllBaseAddress + pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
//	pAddressTable = (PDWORD)(DllBaseAddress + pExportDir->AddressOfFunctions);
//	pNameOrdTable = (PWORD)(DllBaseAddress + pExportDir->AddressOfNameOrdinals);
//	pNameTable = (PDWORD)(DllBaseAddress + pExportDir->AddressOfNames);
//	pTextSection = (PIMAGE_SECTION_HEADER)((UINT64)(&pNtHdr->OptionalHeader) + pNtHdr->FileHeader.SizeOfOptionalHeader);
//	dwNumberOfSections = pNtHdr->FileHeader.NumberOfSections;
//	for (i = 0; i < dwNumberOfSections; i++) {
//		pTextSection += i;
//		if (pTextSection->Name[0] == '.' && pTextSection->Name[1] == 't' && pTextSection->Name[2] == 'e' && pTextSection->Name[3] == 'x' && pTextSection->Name[4] == 't' && pTextSection->Name[5] == '\0') {
//			break;
//		}
//	}
//
//	for (i = 0; i < pExportDir->NumberOfNames; i++) {
//		lpFunctionName = (LPSTR)(DllBaseAddress + pNameTable[i]);
//		if (HASHA(lpFunctionName) == dwHash) {
//			dwFunctionRVA = pAddressTable[pNameOrdTable[i]];
//			if (dwFunctionRVA >= pTextSection->VirtualAddress && dwFunctionRVA < pTextSection->VirtualAddress + pTextSection->Misc.VirtualSize) {
//				pResult = (FARPROC)(DllBaseAddress + dwFunctionRVA);
//			}
//			else {
//				lpProcInfo = (LPSTR)(DllBaseAddress + dwFunctionRVA);
//				while (lpProcInfo[j] != '\0') {
//					if (lpProcInfo[j] == '.') {
//						break;
//					}
//
//					j++;
//				}
//
//				if (lpProcInfo[j] == '.') {
//					lpFunctionName = &lpProcInfo[j + 1];
//					memcpy(szDllName, lpProcInfo, j);
//					szDllName[j] = '.';
//					szDllName[j + 1] = 'D';
//					szDllName[j + 2] = 'L';
//					szDllName[j + 3] = 'L';
//					szDllName[j + 4] = '\0';
//					pResult = GetProcAddressH(HASHA(szDllName), HASHA(lpFunctionName));
//				}
//			}
//
//			break;
//		}
//	}
//
//	return pResult;
//}