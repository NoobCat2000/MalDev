#include "pch.h"

UINT64 GetCurrentTimeStamp(VOID)
{
	UINT64 uResult = 0;
	FILETIME FileTime;
	ULARGE_INTEGER LargeInteger;

	GetSystemTimeAsFileTime(&FileTime);
	LargeInteger.LowPart = FileTime.dwLowDateTime;
	LargeInteger.HighPart = FileTime.dwHighDateTime;

	uResult = (LargeInteger.QuadPart - 116444736000000000ULL) / 10000000ULL;
	return uResult;
}

INT GetUTFOffset(VOID)
{
	TIME_ZONE_INFORMATION TimeZone;
	CHAR szTimeZone[0x10];

	SecureZeroMemory(&TimeZone, sizeof(TimeZone));
	GetTimeZoneInformation(&TimeZone);

	return TimeZone.Bias / (-60);
}