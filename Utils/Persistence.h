#pragma once

BOOL WTStartPersistence
(
	_In_ LPSTR lpCommandLine
);

BOOL PersistenceMethod1
(
	_In_ LPSTR lpCommandLine
);

BOOL PersistenceMethod2
(
	_In_ LPSTR lpCommandLine,
	_In_ PGLOBAL_CONFIG pConfig
);