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
	//IAction* pIAction = NULL;
	IExecAction2* pIAction = NULL;
	VARIANT ServerName, User, Domain, Password;
	ITaskFolder* pFolder = NULL;
	BSTR TaskRun = NULL;

	hResult = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hResult)) {
		LogError(L"CoInitializeEx failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	hResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (FAILED(hResult)) {
		LogError(L"CoInitializeSecurity failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	hResult = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER, &IID_ITaskService, &pITaskService);
	if (FAILED(hResult)) {
		LogError(L"CoCreateInstance failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
		goto CLEANUP;
	}

	VariantInit(&Domain);
	VariantInit(&User);
	VariantInit(&ServerName);
	VariantInit(&Password);
	hResult = pITaskService->lpVtbl->Connect(pITaskService, ServerName, User, Domain, Password);
	if (FAILED(hResult)) {
		LogError(L"Connect failed at %lls\n", __FUNCTIONW__);
		goto CLEANUP;
	}

	hResult = pITaskService->lpVtbl->GetFolder(pITaskService, NULL, &pFolder);
	if (FAILED(hResult)) {
		LogError(L"GetFolder failed at %lls\n", __FUNCTIONW__);
		goto CLEANUP;
	}

	hResult = pITaskService->lpVtbl->NewTask(pITaskService, 0, &pITaskDefinition);
	if (FAILED(hResult)) {
		LogError(L"NewTask failed at %lls\n", __FUNCTIONW__);
		goto CLEANUP;
	}

	hResult = pITaskDefinition->lpVtbl->get_Actions(pITaskDefinition, &pIActionCollection);
	if (FAILED(hResult)) {
		LogError(L"get_Actions failed at %lls\n", __FUNCTIONW__);
		goto CLEANUP;
	}

	hResult = pIActionCollection->lpVtbl->Create(pIActionCollection, TASK_ACTION_EXEC, &pIAction);
	if (FAILED(hResult)) {
		LogError(L"Create failed at %lls\n", __FUNCTIONW__);
		goto CLEANUP;
	}

	TaskRun = SysAllocString(lpCommandLine);
	hResult = pIAction->lpVtbl->put_Path(pIAction, TaskRun);
	if (FAILED(hResult)) {
		LogError(L"put_Path failed at %lls\n", __FUNCTIONW__);
		goto CLEANUP;
	}

	Result = TRUE;
CLEANUP:
	CoUninitialize();
	if (TaskRun != NULL) {
		SysFreeString(TaskRun);
	}

	if (pIAction != NULL) {
		pIAction->lpVtbl->Release(pIAction);
	}


	return Result;
}