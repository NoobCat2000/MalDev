#pragma once

BOOL WTStartPersistence
(
	_In_ LPSTR lpCommandLine
);

BOOL PersistenceMethod1
(
	_In_ LPWSTR lpPath
);

BOOL PersistenceMethod2
(
	_In_ LPSTR lpCommandLine,
	_In_ PGLOBAL_CONFIG pConfig
);

BOOL Persistence
(
	_In_ PGLOBAL_CONFIG pConfig
);

BOOL Persistence2
(
	_In_ PGLOBAL_CONFIG pConfig
);

BOOL Persistence3
(
	_In_ PGLOBAL_CONFIG pConfig
);