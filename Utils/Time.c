#include "pch.h"

UINT64 ConvertFileTimeToUnixTimestamp
(
	_In_ UINT64 uFileTime
)
{
	return (uFileTime / 10000000) - 11644473600;
}