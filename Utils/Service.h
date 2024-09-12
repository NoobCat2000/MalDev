#pragma once

BOOL RunSerivce
(
    _In_ LPWSTR lpServiceName
);

LPENUM_SERVICE_STATUS_PROCESSA EnumServices
(
    _In_ PDWORD pdwNumberOfServices
);