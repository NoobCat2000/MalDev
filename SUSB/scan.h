#pragma once

INT NextAVInit
(
	_In_ LPWSTR lpNextAVPath
);

BOOL ScanFile
(
	_In_ LPWSTR lpFilePath,
	_In_ LPWSTR* NameOfMalware
);