#pragma once

BOOL StartTask
(
	_In_ LPWSTR lpTaskName
);

BOOL CreateAtLogonTask
(
	_In_ LPWSTR lpTaskName,
	_In_ LPSTR lpFolder,
	_In_ LPWSTR lpCommandLine
);

BOOL CreateTimeTriggerTask
(
	_In_ LPWSTR lpTaskName,
	_In_ LPWSTR lpFolder,
	_In_ LPWSTR lpCommandLine,
	_In_ BSTR Interval
);

BOOL IsScheduledTaskExist
(
	_In_ LPWSTR lpTaskName,
	_In_ LPWSTR lpFolderPath
);