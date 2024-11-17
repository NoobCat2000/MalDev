#include "pch.h"

BOOL StartTask
(
	_In_ LPWSTR lpTaskName
)
{
	HRESULT hr = S_OK;
	ITaskService* pITaskService = NULL;
	BOOL bResult = FALSE;
	ITaskFolder* pFolder = NULL;
	IRegisteredTask* pRegisteredTask = NULL;
	VARIANT Args;
	IRunningTask* pRunningTask = NULL;
	VARIANT ServerName, User, Domain, Password;
	TASK_STATE TaskState;

	hr = CoInitialize(NULL);
	if (FAILED(hr)) {
		goto END;
	}

	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService, &pITaskService);
	if (FAILED(hr)) {
		goto END;
	}

	VariantInit(&Domain);
	VariantInit(&User);
	VariantInit(&ServerName);
	VariantInit(&Password);
	hr = pITaskService->lpVtbl->Connect(pITaskService, ServerName, User, Domain, Password);
	if (FAILED(hr)) {
		goto END;
	}

	hr = pITaskService->lpVtbl->GetFolder(pITaskService, NULL, &pFolder);
	if (FAILED(hr)) {
		goto END;
	}

	hr = pFolder->lpVtbl->GetTask(pFolder, lpTaskName, &pRegisteredTask);
	if (FAILED(hr)) {
		goto END;
	}

	hr = pRegisteredTask->lpVtbl->get_State(pRegisteredTask, &TaskState);
	if (FAILED(hr)) {
		goto END;
	}

	if (TaskState == TASK_STATE_DISABLED || TaskState == TASK_STATE_RUNNING) {
		goto END;
	}

	VariantInit(&Args);
	hr = pRegisteredTask->lpVtbl->Run(pRegisteredTask, Args, NULL);
	if (FAILED(hr)) {
		goto END;
	}

	bResult = TRUE;
END:
	if (pRegisteredTask != NULL) {
		pRegisteredTask->lpVtbl->Release(pRegisteredTask);
	}

	if (pFolder != NULL) {
		pFolder->lpVtbl->Release(pFolder);
	}

	if (pITaskService != NULL) {
		pITaskService->lpVtbl->Release(pITaskService);
	}

	CoUninitialize();
	return bResult;
}

BOOL CreateAtLogonTask
(
	_In_ LPWSTR lpTaskName,
	_In_ LPWSTR lpCommandLine
)
{
	HRESULT hResult;
	BOOL Result = FALSE;
	ITaskService* pITaskService = NULL;
	ITaskDefinition* pITaskDefinition = NULL;
	IActionCollection* pIActionCollection = NULL;
	ITriggerCollection* pITriggerCollection = NULL;
	ILogonTrigger* pILogonTrigger = NULL;
	ITrigger* pITrigger = NULL;
	IAction* pIAction = NULL;
	IRegisteredTask* pIRegisteredTask = NULL;
	IExecAction2* pIExecAction2 = NULL;
	VARIANT ServerName, User, Domain, Password, UserId, Sddl;
	ITaskFolder* pFolder = NULL;
	IRegistrationInfo* pIRegistrationInfo = NULL;
	BSTR TaskRun = NULL;
	BSTR TaskName = NULL;
	WCHAR wszTemp[0x100];
	DWORD cbTemp = _countof(wszTemp);
	SYSTEMTIME SystemTime;
	WCHAR wszNullStr[0x10];

	SecureZeroMemory(wszNullStr, sizeof(wszNullStr));
	hResult = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hResult)) {
		LOG_ERROR("CoInitializeEx", hResult);
		goto CLEANUP;
	}

	hResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (FAILED(hResult)) {
		LOG_ERROR("CoInitializeSecurity", hResult);
		goto CLEANUP;
	}

	hResult = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER, &IID_ITaskService, &pITaskService);
	if (FAILED(hResult)) {
		LOG_ERROR("CoCreateInstance", hResult);
		goto CLEANUP;
	}

	VariantInit(&Domain);
	VariantInit(&User);
	VariantInit(&ServerName);
	VariantInit(&Password);
	hResult = pITaskService->lpVtbl->Connect(pITaskService, ServerName, User, Domain, Password);
	if (FAILED(hResult)) {
		LOG_ERROR("pITaskService->Connect", hResult);
		goto CLEANUP;
	}

	hResult = pITaskService->lpVtbl->GetFolder(pITaskService, NULL, &pFolder);
	if (FAILED(hResult)) {
		LOG_ERROR("pITaskService->GetFolder", hResult);
		goto CLEANUP;
	}

	hResult = pITaskService->lpVtbl->NewTask(pITaskService, 0, &pITaskDefinition);
	if (FAILED(hResult)) {
		LOG_ERROR("pITaskService->NewTask", hResult);
		goto CLEANUP;
	}

	hResult = pITaskDefinition->lpVtbl->get_Actions(pITaskDefinition, &pIActionCollection);
	if (FAILED(hResult)) {
		LOG_ERROR("pITaskDefinition->get_Actions", hResult);
		goto CLEANUP;
	}

	hResult = pIActionCollection->lpVtbl->Create(pIActionCollection, TASK_ACTION_EXEC, &pIAction);
	if (FAILED(hResult)) {
		LOG_ERROR("pIActionCollection->Create", hResult);
		goto CLEANUP;
	}

	hResult = pIAction->lpVtbl->QueryInterface(pIAction, &IID_IExecAction2, &pIExecAction2);
	if (FAILED(hResult)) {
		LOG_ERROR("pIAction->QueryInterface", hResult);
		goto CLEANUP;
	}

	TaskRun = SysAllocString(lpCommandLine);
	hResult = pIExecAction2->lpVtbl->put_Path(pIAction, TaskRun);
	if (FAILED(hResult)) {
		LOG_ERROR("pIExecAction2->put_Path", hResult);
		goto CLEANUP;
	}

	hResult = pITaskDefinition->lpVtbl->get_Triggers(pITaskDefinition, &pITriggerCollection);
	if (FAILED(hResult)) {
		LOG_ERROR("pITaskDefinition->get_Triggers", hResult);
		goto CLEANUP;
	}

	hResult = pITriggerCollection->lpVtbl->Create(pITriggerCollection, TASK_TRIGGER_LOGON, &pITrigger);
	if (FAILED(hResult)) {
		LOG_ERROR("pITriggerCollection->Create", hResult);
		goto CLEANUP;
	}

	hResult = pITrigger->lpVtbl->QueryInterface(pITrigger, &IID_ILogonTrigger, &pILogonTrigger);
	if (FAILED(hResult)) {
		LOG_ERROR("pITrigger->QueryInterface", hResult);
		goto CLEANUP;
	}

	hResult = pITaskDefinition->lpVtbl->get_RegistrationInfo(pITaskDefinition, &pIRegistrationInfo);
	if (FAILED(hResult)) {
		LOG_ERROR("pITaskDefinition->get_RegistrationInfo", hResult);
		goto CLEANUP;
	}

	RtlSecureZeroMemory(wszTemp, sizeof(wszTemp));
	GetComputerNameW(wszTemp, &cbTemp);
	lstrcatW(wszTemp, L"\\");
	cbTemp -= lstrlenW(wszTemp);
	GetUserNameW(wszTemp + lstrlenW(wszTemp), &cbTemp);
	hResult = pIRegistrationInfo->lpVtbl->put_Author(pIRegistrationInfo, wszTemp);
	if (FAILED(hResult)) {
		LOG_ERROR("pIRegistrationInfo->put_Author", hResult);
		goto CLEANUP;
	}

	RtlSecureZeroMemory(&SystemTime, sizeof(SystemTime));
	RtlSecureZeroMemory(wszTemp, sizeof(wszTemp));
	GetLocalTime(&SystemTime);
	wsprintfW(wszTemp, L"%d-%02d-%02dT%02d:%02d:%02d", SystemTime.wYear, SystemTime.wMonth, SystemTime.wDay, SystemTime.wHour, SystemTime.wMinute, SystemTime.wSecond);
	hResult = pIRegistrationInfo->lpVtbl->put_Date(pIRegistrationInfo, wszTemp);
	if (FAILED(hResult)) {
		LOG_ERROR("pIRegistrationInfo->put_Date", hResult);
		goto CLEANUP;
	}

	TaskName = SysAllocString(lpTaskName);
	VariantInit(&UserId);
	VariantInit(&Sddl);
	Sddl.vt = VT_BSTR;
	Sddl.bstrVal = SysAllocString(wszNullStr);
	hResult = pFolder->lpVtbl->RegisterTaskDefinition(pFolder, TaskName, pITaskDefinition, TASK_CREATE, UserId, Password, TASK_LOGON_INTERACTIVE_TOKEN, Sddl, &pIRegisteredTask);
	VariantClear(&Sddl);
	if (FAILED(hResult)) {
		LOG_ERROR("pFolder->RegisterTaskDefinition", hResult);
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	CoUninitialize();
	if (TaskRun != NULL) {
		SysFreeString(TaskRun);
	}

	if (pILogonTrigger != NULL) {
		pILogonTrigger->lpVtbl->Release(pILogonTrigger);
	}

	if (pITrigger != NULL) {
		pITrigger->lpVtbl->Release(pITrigger);
	}

	if (pITriggerCollection != NULL) {
		pITriggerCollection->lpVtbl->Release(pITriggerCollection);
	}

	if (pIExecAction2 != NULL) {
		pIExecAction2->lpVtbl->Release(pIExecAction2);
	}

	if (pIAction != NULL) {
		pIAction->lpVtbl->Release(pIAction);
	}

	if (pIActionCollection != NULL) {
		pIActionCollection->lpVtbl->Release(pIActionCollection);
	}

	if (TaskName != NULL) {
		SysFreeString(TaskName);
	}

	if (pIRegisteredTask != NULL) {
		pIRegisteredTask->lpVtbl->Release(pIRegisteredTask);
	}

	if (pIRegistrationInfo != NULL) {
		pIRegistrationInfo->lpVtbl->Release(pIRegistrationInfo);
	}

	if (pITaskDefinition != NULL) {
		pITaskDefinition->lpVtbl->Release(pITaskDefinition);
	}

	if (pFolder != NULL) {
		pFolder->lpVtbl->Release(pFolder);
	}

	if (pITaskService != NULL) {
		pITaskService->lpVtbl->Release(pITaskService);
	}

	return Result;
}