#include "pch.h"

DWORD GetServiceState
(
    _In_ SC_HANDLE ServiceHandle
)
{
    SERVICE_STATUS_PROCESS svcStatus;
    ULONG uTemp = 0;

    if (QueryServiceStatusEx(ServiceHandle, SC_STATUS_PROCESS_INFO, &svcStatus, sizeof(svcStatus), &uTemp)) {
        return svcStatus.dwCurrentState;
    }

    LogError(L"QueryServiceStatusEx failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
    return SERVICE_STOPPED;
}

BOOL RunSerivce
(
    _In_ LPWSTR lpServiceName
)
{
    BOOL Result = FALSE;
    SC_HANDLE schManager = NULL, schService = NULL;
    DWORD dwState, dwRetryCount;

    do {
        schManager = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
        if (schManager == NULL) {
            LogError(L"OpenSCManagerW failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
            goto CLEANUP;
        }

        schService = OpenServiceW(schManager, lpServiceName, SERVICE_QUERY_STATUS | SERVICE_START);
        if (schService == NULL) {
            LogError(L"OpenServiceW failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
            goto CLEANUP;
        }

        dwState = GetServiceState(schService);
        if (dwState == SERVICE_RUNNING) {
            break;
        }

        if (dwState == SERVICE_PAUSE_PENDING || dwState == SERVICE_STOP_PENDING) {
            dwRetryCount = 5;
            do {
                dwState = GetServiceState(schService);
                if (dwState == SERVICE_RUNNING) {
                    Result = TRUE;
                    goto CLEANUP;
                }

                Sleep(1000);
            } while (--dwRetryCount);
        }

        if (dwState == SERVICE_STOPPED) {
            if (StartServiceW(schService, 0, NULL)) {
                Sleep(1000);
                dwState = GetServiceState(schService);
                if (dwState == SERVICE_RUNNING) {
                    Result = TRUE;
                    break;
                }
            }
            else {
                LogError(L"StartServiceW failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
                goto CLEANUP;
            }
        }

    } while (FALSE);

    Result = TRUE;
CLEANUP:
    if (schService != NULL) {
        CloseServiceHandle(schService);
    }

    if (schManager != NULL) {
        CloseServiceHandle(schManager);
    }

    return Result;
}