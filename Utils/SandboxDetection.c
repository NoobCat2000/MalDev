#include "pch.h"

DWORD ParseMemoryMap
(
	_In_ PMEMORY_REGION pRegions,
	_In_ PMAP_KEY pKey
)
{
	HKEY hKey = NULL;
	PBYTE pData = NULL;
	DWORD dwLength = 0, dwResult = 0, dwType = 0;;
	LSTATUS Status = ERROR_SUCCESS;
	PCM_RESOURCE_LIST ResourceList = NULL;
	DWORD i = 0;
	DWORD j = 0;

	if ((Status = RegOpenKeyA(HKEY_LOCAL_MACHINE, pKey->lpKeyPath, &hKey)) != ERROR_SUCCESS) {
		LOG_ERROR("RegOpenKeyA", Status);
		goto CLEANUP;
	}

	if ((Status = RegQueryValueExA(hKey, pKey->lpValueName, 0, &dwType, NULL, &dwLength)) != ERROR_SUCCESS) {
		LOG_ERROR("RegOpenKeyW", Status);
		goto CLEANUP;
	}

	pData = ALLOC(dwLength);
	RegQueryValueExA(hKey, pKey->lpValueName, 0, &dwType, pData, &dwLength);
	ResourceList = (PCM_RESOURCE_LIST)pData;
	for (i = 0; i < ResourceList->Count; i++) {
		for (j = 0; j < ResourceList->List[0].PartialResourceList.Count; j++) {
			if (ResourceList->List[i].PartialResourceList.PartialDescriptors[j].Type == 3) {
				if (pRegions != NULL) {
					pRegions->uAddress = ResourceList->List[i].PartialResourceList.PartialDescriptors[j].u.Memory.Start.QuadPart;
					pRegions->uSize = ResourceList->List[i].PartialResourceList.PartialDescriptors[j].u.Memory.Length;
					pRegions++;
				}

				dwResult++;
			}
		}
	}

CLEANUP:
	if (hKey != NULL) {
		RegCloseKey(hKey);
	}

	if (pData != NULL) {
		FREE(pData);
	}

	return dwResult;
}

DWORD CheckVMResource
(
	_In_ PMEMORY_REGION pPhysicalMem,
	_In_ DWORD cPhysicalMem,
	_In_ PMEMORY_REGION pReservedMem,
	_In_ DWORD cReservedMem,
	_In_ PMEMORY_REGION pLoaderReserved,
	_In_ DWORD cLoaderReserved
)
{
	ULONG64 VBOX_PHYS_LO = 0x0000000000001000ULL;
	ULONG64 VBOX_PHYS_HI = 0x000000000009f000ULL;
	ULONG64 HYPERV_PHYS_LO = 0x0000000000001000ULL;
	ULONG64 HYPERV_PHYS_HI = 0x00000000000a0000ULL;
	ULONG64 RESERVED_ADDR_LOW = 0x0000000000001000ULL;
	ULONG64 LOADER_RESERVED_ADDR_LOW = 0x0000000000000000ULL;
	ULONG64 uLowestReservedAddrRangeEnd = 0;
	ULONG64 uLowestLoaderReservedAddrRangeEnd = 0;
	DWORD i = 0;

	if (cPhysicalMem == 0 || cReservedMem == 0 || cLoaderReserved == 0) {
		return VM_RESOURCE_CHECK_ERROR;
	}

	if (pPhysicalMem == NULL || pReservedMem == NULL || pLoaderReserved == NULL) {
		return VM_RESOURCE_CHECK_ERROR;
	}

	for (i = 0; i < cReservedMem; i++) {
		if (pReservedMem[i].uAddress == RESERVED_ADDR_LOW) {
			uLowestReservedAddrRangeEnd = pReservedMem[i].uAddress + pReservedMem[i].uSize;
			break;
		}
	}

	if (uLowestReservedAddrRangeEnd == 0) {
		return VM_RESOURCE_CHECK_ERROR;
	}

	for (i = 0; i < cLoaderReserved; i++) {
		if (pLoaderReserved[i].uAddress == LOADER_RESERVED_ADDR_LOW) {
			uLowestLoaderReservedAddrRangeEnd = pLoaderReserved[i].uAddress + pLoaderReserved[i].uSize;
			break;
		}
	}

	if (uLowestLoaderReservedAddrRangeEnd == 0) {
		return VM_RESOURCE_CHECK_ERROR;
	}

	if (uLowestReservedAddrRangeEnd != uLowestLoaderReservedAddrRangeEnd) {
		return VM_RESOURCE_CHECK_NO_VM;
	}

	for (int i = 0; i < cPhysicalMem; i++) {
		if (pPhysicalMem[i].uAddress == HYPERV_PHYS_LO && (pPhysicalMem[i].uAddress + pPhysicalMem[i].uSize) == HYPERV_PHYS_HI) {
			return VM_RESOURCE_CHECK_HYPERV;
		}

		if (pPhysicalMem[i].uAddress == VBOX_PHYS_LO && (pPhysicalMem[i].uAddress + pPhysicalMem[i].uSize) == VBOX_PHYS_HI) {
			return VM_RESOURCE_CHECK_VBOX;
		}
	}

	return VM_RESOURCE_CHECK_UNKNOWN_PLATFORM;
}

BOOL DetectSandbox1()
{
	MAP_KEY ResourceRegistryKeys[] = {
		{
			"Hardware\\ResourceMap\\System Resources\\Physical Memory",
			".Translated"
		},
		{
			"Hardware\\ResourceMap\\System Resources\\Reserved",
			".Translated"
		},
		{
			"Hardware\\ResourceMap\\System Resources\\Loader Reserved",
			".Raw"
		}
	};
	DWORD dwCount = 0;
	PMEMORY_REGION Regions[3];
	DWORD RegionCounts[3];
	DWORD i = 0;
	DWORD j = 0;
	DWORD dwCheckResult = 0;
	BOOL Result = FALSE;

	SecureZeroMemory(Regions, sizeof(Regions));
	for (i = 0; i < _countof(Regions); i++) {
		dwCount = ParseMemoryMap(NULL, &ResourceRegistryKeys[i]);
		if (dwCount == 0) {
			goto CLEANUP;
		}

		Regions[i] = ALLOC(sizeof(MEMORY_REGION) * dwCount);
		dwCount = ParseMemoryMap(Regions[i], &ResourceRegistryKeys[i]);
		RegionCounts[i] = dwCount;
	}

	dwCheckResult = CheckVMResource(Regions[VM_RESOURCE_CHECK_REGKEY_PHYSICAL], RegionCounts[VM_RESOURCE_CHECK_REGKEY_PHYSICAL], Regions[VM_RESOURCE_CHECK_REGKEY_RESERVED], RegionCounts[VM_RESOURCE_CHECK_REGKEY_RESERVED], Regions[VM_RESOURCE_CHECK_REGKEY_LOADER_RESERVED], RegionCounts[VM_RESOURCE_CHECK_REGKEY_LOADER_RESERVED]
	);

	if (dwCheckResult == VM_RESOURCE_CHECK_HYPERV || dwCheckResult == VM_RESOURCE_CHECK_VBOX) {
		Result = TRUE;
	}
	
CLEANUP:
	for (i = 0; i < _countof(Regions); i++) {
		FREE(Regions[i]);
	}

	return Result;
}

BOOL DetectSandbox2()
{
	LPSTR BlacklistedHypervisors[] = { "KVMKVMKVM\0\0\0", "Microsoft Hv", "VMwareVMware", "XenVMMXenVMM", "prl hyperv  ", "VBoxVBoxVBox" };
	DWORD i = 0;
	BOOL Result = FALSE;
	DWORD CPUInfo[4];
	CHAR szHypervisorVendor[0x40];

	__cpuid(CPUInfo, 0x40000000);
	SecureZeroMemory(szHypervisorVendor, sizeof(szHypervisorVendor));
	memcpy(szHypervisorVendor, CPUInfo + 1, 12);
	for (int i = 0; i < _countof(BlacklistedHypervisors); i++) {
		if (!lstrcmpA(szHypervisorVendor, BlacklistedHypervisors[i])) {
			Result = TRUE;
			goto CLEANUP;
		}
	}

CLEANUP:
	return Result;
}

BOOL DetectSandbox3()
{
	DWORD dwNumberOfProcessors = 0;

	dwNumberOfProcessors = NumberOfProcessors();
	if (dwNumberOfProcessors < 2) {
		return TRUE;
	}

	return FALSE;
}

BOOL DetectSandbox4()
{
	LPSTR Paths[] = {
		"System32\\drivers\\vmnet.sys",
		"System32\\drivers\\vmmouse.sys",
		"System32\\drivers\\vmusb.sys",
		"System32\\drivers\\vm3dmp.sys",
		"System32\\drivers\\vmci.sys",
		"System32\\drivers\\vmhgfs.sys",
		"System32\\drivers\\vmmemctl.sys",
		"System32\\drivers\\vmx86.sys",
		"System32\\drivers\\vmrawdsk.sys",
		"System32\\drivers\\vmusbmouse.sys",
		"System32\\drivers\\vmkdb.sys",
		"System32\\drivers\\vmnetuserif.sys",
		"System32\\drivers\\vmnetadapter.sys",
	};
	DWORD i = 0;
	PVOID pOldValue = NULL;
	BOOL IsWow64 = FALSE;
	BOOL Result = FALSE;
	CHAR szWinDir[MAX_PATH];
	CHAR szPath[MAX_PATH];

	GetWindowsDirectoryA(szWinDir, MAX_PATH);
	IsWow64Process(GetCurrentProcess(), &IsWow64);
	if (IsWow64) {
		Wow64DisableWow64FsRedirection(&pOldValue);
	}

	for (i = 0; i < _countof(Paths); i++) {
		wsprintfA(szPath, "%s\\%s", szWinDir, Paths[i]);
		if (IsFileExist(szPath)) {
			Result = TRUE;
			break;
		}
	}

	if (IsWow64) {
		Wow64RevertWow64FsRedirection(&pOldValue);
	}

	return Result;
}

BOOL DetectSandbox5()
{
	LPSTR szProcesses[] = {
		"qemu-ga.exe",
		"vdagent.exe",
		"vdservice.exe",
		"vboxservice.exe",
		"vboxtray.exe",
		"vmtoolsd.exe",
		"vmwaretray.exe",
		"vmwareuser.exe",
		"VGAuthService.exe",
		"vmacthlp.exe"
	};
	BOOL Result = FALSE;

	if (AreProcessesRunning(szProcesses, _countof(szProcesses), 0)) {
		Result = TRUE;
	}

	return Result;
}