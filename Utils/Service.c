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

    LOG_ERROR("QueryServiceStatusEx", GetLastError());
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
            LOG_ERROR("OpenSCManagerW", GetLastError());
            goto CLEANUP;
        }

        schService = OpenServiceW(schManager, lpServiceName, SERVICE_QUERY_STATUS | SERVICE_START);
        if (schService == NULL) {
            LOG_ERROR("OpenServiceW", GetLastError());
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
                LOG_ERROR("StartServiceW", GetLastError());
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
    DWORD dwLastError = ERROR_SUCCESS;

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
        LOG_ERROR("OpenSCManagerA", GetLastError());
        goto CLEANUP;
    }

    pServices = ALLOC(cbServices);
    while (TRUE) {
        dwReturnedLength = 0;
        if (!EnumServicesStatusExA(hScManager, SC_ENUM_PROCESS_INFO, dwType, SERVICE_STATE_ALL, pServices, cbServices, &dwReturnedLength, &dwReturnedServices, NULL, NULL)) {
            dwLastError = GetLastError();
            if (dwLastError == ERROR_MORE_DATA) {
                cbServices += dwReturnedLength + 0x400;
                pServices = REALLOC(pServices, cbServices);
                continue;
            }
            else {
                FREE(pServices);
                pServices = NULL;
                LOG_ERROR("EnumServicesStatusExA", dwLastError);
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

BOOL StopDependentServices
(
    _In_ LPSTR lpServiceName,
    _In_ LPSTR lpHostname
)
{
    SC_HANDLE ScManager = NULL;
    SC_HANDLE hService = NULL;
    SC_HANDLE hDepService = NULL;
    BOOL Result = FALSE;
    LPENUM_SERVICE_STATUS lpDependencies = NULL;
    LPENUM_SERVICE_STATUS lpDepService = NULL;
    SERVICE_STATUS_PROCESS ServiceStatus;
    DWORD dwBytesNeeded = 0;
    DWORD dwCount = 0;
    DWORD dwLastError = ERROR_SUCCESS;
    DWORD i = 0;
    DWORD dwStartTime = 0;
    LPWSTR lpTemp = NULL;
    DWORD dwTimeout = 30000;

    ScManager = OpenSCManagerA(lpHostname, NULL, SC_MANAGER_ALL_ACCESS);
    if (ScManager == NULL) {
        LOG_ERROR("OpenSCManagerA", GetLastError());
        goto CLEANUP;
    }

    hService = OpenServiceA(ScManager, lpServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
    if (hService == NULL) {
        LOG_ERROR("OpenServiceA", GetLastError());
        goto CLEANUP;
    }

    if (EnumDependentServicesA(hService, SERVICE_ACTIVE, lpDependencies, 0, &dwBytesNeeded, &dwCount)) {
        Result = TRUE;
        goto CLEANUP;
    }
    else {
        dwLastError = GetLastError();
        if (dwLastError != ERROR_MORE_DATA) {
            LOG_ERROR("EnumDependentServicesA", dwLastError);
            goto CLEANUP;
        }

        lpDependencies = ALLOC(dwBytesNeeded);
        if (!EnumDependentServicesA(hService, SERVICE_ACTIVE, lpDependencies, dwBytesNeeded, &dwBytesNeeded, &dwCount)) {
            LOG_ERROR("EnumDependentServicesA", dwLastError);
            goto CLEANUP;
        }

        for (i = 0; i < dwCount; i++) {
            lpDepService = &lpDependencies[i];
            hDepService = OpenServiceA(ScManager, lpDepService->lpServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
            if (hDepService == NULL) {
                LOG_ERROR("OpenServiceA", dwLastError);
                goto CLEANUP;
            }

            SecureZeroMemory(&ServiceStatus, sizeof(ServiceStatus));
            if (!ControlService(hDepService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ServiceStatus)) {
                CloseServiceHandle(hDepService);
                LOG_ERROR("ControlService", dwLastError);
                goto CLEANUP;
            }

            dwStartTime = GetTickCount();
            while (ServiceStatus.dwCurrentState != SERVICE_STOPPED) {
                Sleep(ServiceStatus.dwWaitHint);
                if (!QueryServiceStatusEx(hDepService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ServiceStatus, sizeof(ServiceStatus), &dwBytesNeeded)) {
                    CloseServiceHandle(hDepService);
                    LOG_ERROR("QueryServiceStatusEx", dwLastError);
                    goto CLEANUP;
                }

                if (ServiceStatus.dwCurrentState == SERVICE_STOPPED) {
                    break;
                }

                if (GetTickCount() - dwStartTime > dwTimeout) {
                    lpTemp = ConvertCharToWchar(lpDepService->lpServiceName);
                    LogError(L"Stopping service %s is timed out", lpTemp);
                    FREE(lpTemp);
                    CloseServiceHandle(hDepService);
                    goto CLEANUP;
                }
            }

            CloseServiceHandle(hDepService);
        }
    }

    Result = TRUE;
CLEANUP:
    FREE(lpDependencies);
    if (hService != NULL) {
        CloseServiceHandle(hService);
    }

    if (ScManager != NULL) {
        CloseServiceHandle(ScManager);
    }

    return Result;
}

BOOL StopService
(
    _In_ LPSTR lpServiceName,
    _In_ LPSTR lpHostname
)
{
    SC_HANDLE ScManager = NULL;
    SC_HANDLE hService = NULL;
    BOOL Result = FALSE;
    SERVICE_STATUS_PROCESS ServiceStatus;
    DWORD dwBytesNeeded = 0;
    DWORD dwStartTime = 0;
    DWORD dwWaitTime = 0;
    DWORD dwTimeout = 30000;

    ScManager = OpenSCManagerA(lpHostname, NULL, SC_MANAGER_ALL_ACCESS);
    if (ScManager == NULL) {
        LOG_ERROR("OpenSCManagerA", GetLastError());
        goto CLEANUP;
    }

    hService = OpenServiceA(ScManager, lpServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
    if (hService == NULL) {
        LOG_ERROR("OpenServiceA", GetLastError());
        goto CLEANUP;
    }

    SecureZeroMemory(&ServiceStatus, sizeof(ServiceStatus));
    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ServiceStatus, sizeof(ServiceStatus), &dwBytesNeeded)) {
        LOG_ERROR("QueryServiceStatusEx", GetLastError());
        goto CLEANUP;
    }

    if (ServiceStatus.dwCurrentState != SERVICE_STOPPED) {
        if (ServiceStatus.dwCurrentState == SERVICE_STOP_PENDING) {
            dwStartTime = GetTickCount();
            while (ServiceStatus.dwCurrentState == SERVICE_STOP_PENDING) {
                dwWaitTime = ServiceStatus.dwWaitHint / 10;
                if (dwWaitTime < 1000) {
                    dwWaitTime = 1000;
                }
                else if (dwWaitTime > 10000) {
                    dwWaitTime = 10000;
                }

                Sleep(dwWaitTime);
                if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ServiceStatus, sizeof(ServiceStatus), &dwBytesNeeded)) {
                    LOG_ERROR("QueryServiceStatusEx", GetLastError());
                    goto CLEANUP;
                }

                if (ServiceStatus.dwCurrentState == SERVICE_STOPPED) {
                    break;
                }

                if (GetTickCount() - dwStartTime > dwTimeout) {
                    LogError(L"Stopping service %s is timed out", lpServiceName);
                    goto CLEANUP;
                }
            }
        }
        else {
            if (!StopDependentServices(lpServiceName, lpHostname)) {
                goto CLEANUP;
            }

            if (!ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ServiceStatus)) {
                LOG_ERROR("ControlService", GetLastError());
                goto CLEANUP;
            }

            dwStartTime = GetTickCount();
            while (ServiceStatus.dwCurrentState != SERVICE_STOPPED) {
                Sleep(ServiceStatus.dwWaitHint);
                if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ServiceStatus, sizeof(ServiceStatus), &dwBytesNeeded)) {
                    LOG_ERROR("QueryServiceStatusEx", GetLastError());
                    goto CLEANUP;
                }

                if (ServiceStatus.dwCurrentState == SERVICE_STOPPED) {
                    break;
                }

                if (GetTickCount() - dwStartTime > dwTimeout) {
                    LogError(L"Stopping service %s is timed out", lpServiceName);
                    goto CLEANUP;
                }
            }
        }
    }

    Result = TRUE;
CLEANUP:
    if (hService != NULL) {
        CloseServiceHandle(hService);
    }

    if (ScManager != NULL) {
        CloseServiceHandle(ScManager);
    }

    return Result;
}