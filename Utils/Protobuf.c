#include "pch.h"

PBYTE MarshalStruct
(
	_In_ PPBElement* pElementList,
	_In_ DWORD dwCount
)
{

}

PBYTE MarshalVarInt
(
	_In_ UINT64 uValue,
	_Out_ PDWORD pcbOutput
)
{
	BYTE bTemp = 0;
	DWORD i = 0;
	PBYTE pResult = NULL;

	pResult = ALLOC(sizeof(UINT64) + 2);
	while (TRUE) {
		bTemp = (uValue >> (i * 7)) & 0x7F;
		if (bTemp == 0) {
			i--;
			break;
		}

		pResult[i++] = bTemp | 0x80;
	}

	pResult[i++] &= 0x7F;
	if (pcbOutput != NULL) {
		*pcbOutput = i;
	}

	return pResult;
}

PPBElement CreateBytesElement
(
	_In_ PBYTE pData,
	_In_ DWORD cbData,
	_In_ DWORD dwFieldIdx
)
{
	PPBElement pResult = NULL;
	PBYTE pTemp = NULL;
	DWORD cbTemp = 0;

	pResult = ALLOC(sizeof(PBElement));
	pResult->Type = LengthDelimited;
	pTemp = MarshalVarInt(cbData, &cbTemp);
	pResult->pMarshalledData = ALLOC(cbTemp + cbData);
	memcpy(pResult->pMarshalledData, pTemp, cbTemp);
	memcpy(&pResult->pMarshalledData[cbTemp], pData, cbData);
	pResult->cbMarshalledData = cbTemp + cbData;
	pResult->dwFieldIdx = dwFieldIdx;
	FREE(pTemp);

	return pResult;
}

PPBElement CreateVarIntElement
(
	_In_ UINT64 uValue,
	_In_ DWORD dwFieldIdx
)
{
	PPBElement pResult = NULL;

	pResult = ALLOC(sizeof(PBElement));
	pResult->Type = Varint;
	pResult->pMarshalledData = MarshalVarInt(uValue, &pResult->cbMarshalledData);
	pResult->dwFieldIdx = dwFieldIdx;

	return pResult;
}

PPBElement CreateRepeatedVarIntElement
(
	_In_ PUINT64 pIntList,
	_In_ DWORD dwCount,
	_In_ DWORD dwFieldIdx
)
{
	PPBElement pResult = NULL;
	DWORD i = 0;
	DWORD dwTemp = 0;

	pResult = ALLOC(sizeof(PBElement));
	pResult->Type = Repeated;
	pResult->dwFieldIdx = dwFieldIdx;
	pResult->dwNumberOfSubElement = dwCount;
	pResult->SubElements = ALLOC(dwCount * sizeof(PBElement));
	for (i = 0; i < dwCount; i++) {
		pResult->SubElements[i] = CreateVarIntElement(pIntList[i], 0);
		pResult->cbMarshalledData += pResult->SubElements[i]->cbMarshalledData;
	}

	return pResult;
}

PPBElement CreateRepeatedBytesElement
(
	_In_ PBYTE* pArrayOfBytes,
	_In_ PDWORD pArrayOfSize,
	_In_ DWORD dwCount,
	_In_ DWORD dwFieldIdx
)
{
	PPBElement pResult = NULL;
	DWORD i = 0;
	DWORD dwTemp = 0;

	pResult = ALLOC(sizeof(PBElement));
	pResult->Type = Repeated;
	pResult->dwFieldIdx = dwFieldIdx;
	pResult->dwNumberOfSubElement = dwCount;
	pResult->SubElements = ALLOC(dwCount * sizeof(PBElement));
	for (i = 0; i < dwCount; i++) {
		pResult->SubElements[i] = CreateBytesElement(pArrayOfBytes[i], pArrayOfSize[i], 0);
		pResult->cbMarshalledData += pResult->SubElements[i]->cbMarshalledData;
	}

	return pResult;
}