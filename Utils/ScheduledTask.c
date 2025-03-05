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
	CLSID CLSID_TaskScheduler = { 0x0F87369F, 0x0A4E5, 0x4CFC, { 0xBD, 0x3E, 0x73, 0x0E6, 0x15, 0x45, 0x72, 0xDD } };
	IID IID_ITaskService = { 0x2FABA4C7, 0x4DA9, 0x4013, { 0x96, 0x97, 0x20, 0xCC, 0x3F, 0xD4, 0x0F, 0x85 } };

	CoInitialize(NULL);
	//hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
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
	_In_ LPSTR lpFolder,
	_In_ LPWSTR lpCommandLine
)
{
	HRESULT hResult;
	BOOL Result = FALSE;
	ITaskService* pITaskService = NULL;
	ITaskDefinition* pITaskDefinition = NULL;
	IActionCollection* pIActionCollection = NULL;
	ITriggerCollection* pITriggerCollection = NULL;
	//ILogonTrigger* pILogonTrigger = NULL;
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
	CLSID CLSID_TaskScheduler = { 0x0F87369F, 0x0A4E5, 0x4CFC, { 0xBD, 0x3E, 0x73, 0x0E6, 0x15, 0x45, 0x72, 0xDD } };
	IID IID_ITaskService = { 0x2FABA4C7, 0x4DA9, 0x4013, { 0x96, 0x97, 0x20, 0xCC, 0x3F, 0xD4, 0x0F, 0x85 } };
	IID IID_IExecAction2 = { 0xF2A82542, 0xBDA5, 0x4E6B, { 0x91, 0x43, 0xE2, 0xBF, 0x4F, 0x89, 0x87, 0xB6} };

	SecureZeroMemory(wszNullStr, sizeof(wszNullStr));
	hResult = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hResult)) {
		LOG_ERROR("CoInitializeEx", hResult);
		goto CLEANUP;
	}

	/*hResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (FAILED(hResult)) {
		LOG_ERROR("CoInitializeSecurity", hResult);
		goto CLEANUP;
	}*/

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

	hResult = pITaskService->lpVtbl->GetFolder(pITaskService, lpFolder, &pFolder);
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

	/*hResult = pITrigger->lpVtbl->QueryInterface(pITrigger, &IID_ILogonTrigger, &pILogonTrigger);
	if (FAILED(hResult)) {
		LOG_ERROR("pITrigger->QueryInterface", hResult);
		goto CLEANUP;
	}*/

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
	if (TaskRun != NULL) {
		SysFreeString(TaskRun);
	}

	/*if (pILogonTrigger != NULL) {
		pILogonTrigger->lpVtbl->Release(pILogonTrigger);
	}*/

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

	CoUninitialize();
	return Result;
}

BOOL CreateTimeTriggerTask
(
	_In_ LPWSTR lpTaskName,
	_In_ LPWSTR lpFolder,
	_In_ LPWSTR lpCommandLine,
	_In_ BSTR Interval
)
{
	HRESULT hResult;
	BOOL Result = FALSE;
	ITaskService* pITaskService = NULL;
	ITaskDefinition* pITaskDefinition = NULL;
	IActionCollection* pIActionCollection = NULL;
	ITriggerCollection* pITriggerCollection = NULL;
	ITimeTrigger* pITimeTrigger = NULL;
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
	IRepetitionPattern* pIRepetitionPattern = NULL;
	CLSID CLSID_TaskScheduler = { 0x0F87369F, 0x0A4E5, 0x4CFC, { 0xBD, 0x3E, 0x73, 0x0E6, 0x15, 0x45, 0x72, 0xDD } };
	IID IID_ITaskService = { 0x2FABA4C7, 0x4DA9, 0x4013, { 0x96, 0x97, 0x20, 0xCC, 0x3F, 0xD4, 0x0F, 0x85 } };
	IID IID_IExecAction2 = { 0xF2A82542, 0xBDA5, 0x4E6B, { 0x91, 0x43, 0xE2, 0xBF, 0x4F, 0x89, 0x87, 0xB6} };
	IID IID_ITimeTrigger = { 0xB45747E0, 0xEBA7, 0x4276, { 0x9F, 0x29, 0x85, 0xC5, 0xBB, 0x30, 0, 6} };

	SecureZeroMemory(wszNullStr, sizeof(wszNullStr));
	CoInitializeEx(NULL, COINIT_MULTITHREADED);
	/*hResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (FAILED(hResult)) {
		LOG_ERROR("CoInitializeSecurity", hResult);
		goto CLEANUP;
	}*/

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

	hResult = pITaskService->lpVtbl->GetFolder(pITaskService, lpFolder, &pFolder);
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

	hResult = pITriggerCollection->lpVtbl->Create(pITriggerCollection, TASK_TRIGGER_TIME, &pITrigger);
	if (FAILED(hResult)) {
		LOG_ERROR("pITriggerCollection->Create", hResult);
		goto CLEANUP;
	}

	hResult = pITrigger->lpVtbl->QueryInterface(pITrigger, &IID_ITimeTrigger, &pITimeTrigger);
	if (FAILED(hResult)) {
		LOG_ERROR("pITrigger->QueryInterface", hResult);
		goto CLEANUP;
	}

	hResult = pITimeTrigger->lpVtbl->put_Id(pITimeTrigger, L"Trigger");
	if (FAILED(hResult)) {
		LOG_ERROR("pITimeTrigger->put_Id", hResult);
		goto CLEANUP;
	}

	hResult = pITimeTrigger->lpVtbl->get_Repetition(pITimeTrigger, &pIRepetitionPattern);
	if (FAILED(hResult)) {
		LOG_ERROR("pITimeTrigger->get_Repetition", hResult);
		goto CLEANUP;
	}

	hResult = pIRepetitionPattern->lpVtbl->put_Interval(pIRepetitionPattern, Interval);
	if (FAILED(hResult)) {
		LOG_ERROR("pITimeTrigger->put_Interval", hResult);
		goto CLEANUP;
	}

	hResult = pITimeTrigger->lpVtbl->put_Repetition(pITimeTrigger, pIRepetitionPattern);
	if (FAILED(hResult)) {
		LOG_ERROR("pITimeTrigger->get_Repetition", hResult);
		goto CLEANUP;
	}

	hResult = pITimeTrigger->lpVtbl->put_Enabled(pITimeTrigger, (VARIANT_BOOL)-1);
	if (FAILED(hResult)) {
		LOG_ERROR("pITimeTrigger->put_Enabled", hResult);
		goto CLEANUP;
	}

	hResult = pITimeTrigger->lpVtbl->put_StartBoundary(pITimeTrigger, L"2025-02-10T15:14:00");
	if (FAILED(hResult)) {
		LOG_ERROR("pITimeTrigger->put_StartBoundary", hResult);
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
	if (TaskRun != NULL) {
		SysFreeString(TaskRun);
	}

	if (pIRepetitionPattern != NULL) {
		pIRepetitionPattern->lpVtbl->Release(pIRepetitionPattern);
	}

	if (pITimeTrigger != NULL) {
		pITimeTrigger->lpVtbl->Release(pITimeTrigger);
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

	CoUninitialize();
	return Result;
}

BOOL IsScheduledTaskExist
(
	_In_ LPWSTR lpTaskName,
	_In_ LPWSTR lpFolderPath
)
{
	BOOL Result = FALSE;
	HRESULT hResult;
	ITaskService* pITaskService = NULL;
	VARIANT ServerName, User, Domain, Password;
	ITaskFolder* pFolder = NULL;
	IRegisteredTaskCollection* pRegisteredTasks = NULL;
	DWORD i = 0;
	DWORD dwNumberOfTasks = 0;
	IRegisteredTask* pRegisteredTask = NULL;
	VARIANT Index;
	BSTR TaskName = NULL;
	CLSID CLSID_TaskScheduler = { 0x0F87369F, 0x0A4E5, 0x4CFC, { 0xBD, 0x3E, 0x73, 0x0E6, 0x15, 0x45, 0x72, 0xDD } };
	IID IID_ITaskService = { 0x2FABA4C7, 0x4DA9, 0x4013, { 0x96, 0x97, 0x20, 0xCC, 0x3F, 0xD4, 0x0F, 0x85 } };

	CoInitializeEx(NULL, COINIT_MULTITHREADED);
	/*hResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (FAILED(hResult)) {
		LOG_ERROR("CoInitializeSecurity", hResult);
		goto CLEANUP;
	}*/

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

	hResult = pITaskService->lpVtbl->GetFolder(pITaskService, (BSTR)lpFolderPath, &pFolder);
	if (FAILED(hResult)) {
		LOG_ERROR("pITaskService->GetFolder", hResult);
		goto CLEANUP;
	}

	hResult = pFolder->lpVtbl->GetTasks(pFolder, TASK_ENUM_HIDDEN, &pRegisteredTasks);
	if (FAILED(hResult)) {
		LOG_ERROR("pFolder->GetTasks", hResult);
		goto CLEANUP;
	}

	hResult = pRegisteredTasks->lpVtbl->get_Count(pRegisteredTasks, &dwNumberOfTasks);
	if (FAILED(hResult)) {
		LOG_ERROR("pRegisteredTasks->get_Count", hResult);
		goto CLEANUP;
	}

	for (i = 0; i < dwNumberOfTasks; i++) {
		VariantInit(&Index);
		Index.vt = VT_INT;
		Index.intVal = i;
		hResult = pRegisteredTasks->lpVtbl->get_Item(pRegisteredTasks, Index, &pRegisteredTask);
		if (SUCCEEDED(hResult)) {
			pRegisteredTask->lpVtbl->get_Name(pRegisteredTask, &TaskName);
			if (!lstrcmpW(TaskName, lpTaskName)) {
				pRegisteredTask->lpVtbl->Release(pRegisteredTask);
				Result = TRUE;
				break;
			}

			pRegisteredTask->lpVtbl->Release(pRegisteredTask);
		}
	}

CLEANUP:
	if (pRegisteredTasks != NULL) {
		pRegisteredTasks->lpVtbl->Release(pRegisteredTasks);
	}

	if (pFolder != NULL) {
		pFolder->lpVtbl->Release(pFolder);
	}

	if (pITaskService != NULL) {
		pITaskService->lpVtbl->Release(pITaskService);
	}

	CoUninitialize();
	return Result;
}