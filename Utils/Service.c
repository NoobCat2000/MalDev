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

LPENUM_SERVICE_STATUS_PROCESSA EnumServices
(
    _In_ PDWORD pdwNumberOfServices
)
{
    SC_HANDLE hScManager = NULL;
    DWORD dwWindowsVersion = 0;
    DWORD dwType = 0;
    DWORD cbServices = 0x8000;
    LPENUM_SERVICE_STATUS_PROCESS pServices= NULL;
    DWORD dwReturnedLength = 0;
    DWORD dwReturnedServices = 0;
    DWORD i = 0;

    dwWindowsVersion = GetWindowsVersionEx();
    if (dwWindowsVersion >= WINDOWS_10_RS1) {
        dwType = SERVICE_TYPE_ALL;
    }
    else if (dwWindowsVersion >= WINDOWS_10) {
        dwType = SERVICE_WIN32 | SERVICE_ADAPTER | SERVICE_DRIVER | SERVICE_INTERACTIVE_PROCESS | SERVICE_USER_SERVICE | SERVICE_USERSERVICE_INSTANCE;
    }
    else {
        dwType = SERVICE_DRIVER | SERVICE_WIN32;
    }

    hScManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (hScManager == NULL) {
        LogError(L"OpenSCManagerA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
        goto CLEANUP;
    }

    pServices = ALLOC(cbServices);
    while (TRUE) {
        dwReturnedLength = 0;
        if (!EnumServicesStatusExA(hScManager, SC_ENUM_PROCESS_INFO, dwType, SERVICE_STATE_ALL, pServices, cbServices, &dwReturnedLength, &dwReturnedServices, NULL, NULL)) {
            if (GetLastError() == ERROR_MORE_DATA) {
                cbServices = dwReturnedLength + 0x400;
                pServices = REALLOC(pServices, cbServices);
                continue;
            }
            else {
                FREE(pServices);
                pServices = NULL;
                LogError(L"EnumServicesStatusExA failed at %lls. Error code: 0x%08x\n", __FUNCTIONW__, GetLastError());
                goto CLEANUP;
            }
        }

        break;
    }
    

    if (pdwNumberOfServices != NULL) {
        *pdwNumberOfServices = dwReturnedServices;
    }

CLEANUP:
    if (hScManager != NULL) {
        CloseServiceHandle(hScManager);
    }

    return pServices;
}