#pragma once

BOOL RunSerivce
(
    _In_ LPWSTR lpServiceName
);

LPENUM_SERVICE_STATUS_PROCESSA EnumServices
(
    _In_ PDWORD pdwNumberOfServices
);

BOOL StopDependentServices
(
    _In_ LPSTR lpServiceName,
    _In_ LPSTR lpHostname
);

BOOL StopService
(
    _In_ LPSTR lpServiceName,
    _In_ LPSTR lpHostname
);