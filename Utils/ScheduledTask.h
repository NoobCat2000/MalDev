#pragma once

BOOL StartTask
(
	_In_ LPWSTR lpTaskName
);

BOOL CreateAtLogonTask
(
	_In_ LPWSTR lpTaskName,
	_In_ LPWSTR lpCommandLine
);