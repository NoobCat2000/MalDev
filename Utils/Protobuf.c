#include "pch.h"

PBYTE MarshalVarInt
(
	_In_ UINT64 uValue,
	_Out_ PDWORD pcbOutput
)
{
	UINT64 i = 0;
	PBYTE pResult = NULL;
	DWORD dwNumberOfBits = 64;
	UINT64 uMask = 0;
	DWORD dwMaxLoop = 0;
	UINT64 uTemp = 0;

	for (i = 63; i >= 0; i--) {
		uTemp = uValue;
		if (i >= 32) {
			uMask = (1 << (i - 32));
			uTemp = uValue >> 32;
		}
		else {
			uMask = (1 << i);
		}

		if (uTemp & uMask) {
			break;
		}

		dwNumberOfBits--;
	}

	dwMaxLoop = (dwNumberOfBits - (dwNumberOfBits % 7)) / 7;
	if (dwNumberOfBits % 7) {
		dwMaxLoop++;
	}

	pResult = ALLOC(sizeof(BYTE) * dwMaxLoop);
	for (i = 0; i < dwMaxLoop; i++) {
		pResult[i] = ((uValue >> (i * 7)) & 0x7F) | 0x80;
	}

	pResult[i - 1] &= 0x7F;
	if (pcbOutput != NULL) {
		*pcbOutput = dwMaxLoop;
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
	PBYTE pDataSize = NULL;
	DWORD cbDataSize = 0;
	PBYTE pMarshalledFieldIdx = NULL;
	DWORD cbMarshalledFieldIdx = 0;

	if (pData == NULL || cbData == 0) {
		return NULL;
	}

	pResult = ALLOC(sizeof(PBElement));
	pResult->Type = LengthDelimited;
	if (dwFieldIdx > 0) {
		dwFieldIdx <<= 3;
		dwFieldIdx |= pResult->Type;
		pMarshalledFieldIdx = MarshalVarInt(dwFieldIdx, &cbMarshalledFieldIdx);
	}

	pDataSize = MarshalVarInt(cbData, &cbDataSize);
	pResult->pMarshalledData = ALLOC(cbMarshalledFieldIdx + cbDataSize + cbData);
	if (pMarshalledFieldIdx != NULL) {
		memcpy(pResult->pMarshalledData, pMarshalledFieldIdx, cbMarshalledFieldIdx);
		FREE(pMarshalledFieldIdx);
	}

	memcpy(pResult->pMarshalledData + cbMarshalledFieldIdx, pDataSize, cbDataSize);
	FREE(pDataSize);
	memcpy(&pResult->pMarshalledData[cbDataSize + cbMarshalledFieldIdx], pData, cbData);
	pResult->cbMarshalledData = cbDataSize + cbData + cbMarshalledFieldIdx;

	return pResult;
}

PPBElement CreateVarIntElement
(
	_In_ UINT64 uValue,
	_In_ DWORD dwFieldIdx
)
{
	PPBElement pResult = NULL;
	PBYTE pMarshalledFieldIdx = NULL;
	DWORD cbMarshalledFieldIdx = 0;
	PBYTE pMarshalledData = NULL;
	DWORD cbMarshalledData = 0;

	pResult = ALLOC(sizeof(PBElement));
	pResult->Type = Varint;
	if (dwFieldIdx > 0) {
		dwFieldIdx <<= 3;
		dwFieldIdx |= pResult->Type;
		pMarshalledFieldIdx = MarshalVarInt(dwFieldIdx, &cbMarshalledFieldIdx);
	}

	pMarshalledData = MarshalVarInt(uValue, &cbMarshalledData);
	pResult->pMarshalledData = ALLOC(cbMarshalledData + cbMarshalledFieldIdx);
	if (pMarshalledFieldIdx != NULL) {
		memcpy(pResult->pMarshalledData, pMarshalledFieldIdx, cbMarshalledFieldIdx);
		FREE(pMarshalledFieldIdx);
	}

	memcpy(pResult->pMarshalledData + cbMarshalledFieldIdx, pMarshalledData, cbMarshalledData);
	pResult->cbMarshalledData = cbMarshalledData + cbMarshalledFieldIdx;
	FREE(pMarshalledData);

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
	PBYTE pMarshalledFieldIdx = NULL;
	DWORD cbMarshalledFieldIdx = 0;
	DWORD dwPos = 0;

	pResult = ALLOC(sizeof(PBElement));
	pResult->Type = Repeated;
	pResult->dwNumberOfSubElement = dwCount;
	pResult->SubElements = ALLOC(dwCount * sizeof(PBElement));
	for (i = 0; i < dwCount; i++) {
		pResult->SubElements[i] = CreateVarIntElement(pIntList[i], 0);
		pResult->cbMarshalledData += pResult->SubElements[i]->cbMarshalledData;
	}

	if (dwFieldIdx > 0) {
		pMarshalledFieldIdx = MarshalVarInt(dwFieldIdx, &cbMarshalledFieldIdx);
	}

	pResult->pMarshalledData = ALLOC(pResult->cbMarshalledData + cbMarshalledFieldIdx);
	if (pMarshalledFieldIdx != NULL) {
		memcpy(pResult->pMarshalledData, pMarshalledFieldIdx, cbMarshalledFieldIdx);
		dwPos += cbMarshalledFieldIdx;
		FREE(pMarshalledFieldIdx);
	}

	for (i = 0; i < dwCount; i++) {
		memcpy(&pResult->pMarshalledData[dwPos], pResult->SubElements[i]->pMarshalledData, pResult->SubElements[i]->cbMarshalledData);
		dwPos += pResult->SubElements[i]->cbMarshalledData;
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
	PBYTE pMarshalledFieldIdx = NULL;
	DWORD cbMarshalledFieldIdx = 0;
	DWORD dwPos = 0;

	pResult = ALLOC(sizeof(PBElement));
	pResult->Type = Repeated;
	pResult->dwNumberOfSubElement = dwCount;
	pResult->SubElements = ALLOC(dwCount * sizeof(PBElement));
	for (i = 0; i < dwCount; i++) {
		pResult->SubElements[i] = CreateBytesElement(pArrayOfBytes[i], pArrayOfSize[i], 0);
		pResult->cbMarshalledData += pResult->SubElements[i]->cbMarshalledData;
	}

	if (dwFieldIdx > 0) {
		pMarshalledFieldIdx = MarshalVarInt(dwFieldIdx, &cbMarshalledFieldIdx);
	}

	pResult->pMarshalledData = ALLOC(pResult->cbMarshalledData + cbMarshalledFieldIdx);
	if (pMarshalledFieldIdx != NULL) {
		memcpy(pResult->pMarshalledData, pMarshalledFieldIdx, cbMarshalledFieldIdx);
		dwPos += cbMarshalledFieldIdx;
		FREE(pMarshalledFieldIdx);
	}

	for (i = 0; i < dwCount; i++) {
		memcpy(&pResult->pMarshalledData[dwPos], pResult->SubElements[i]->pMarshalledData, pResult->SubElements[i]->cbMarshalledData);
		dwPos += pResult->SubElements[i]->cbMarshalledData;
	}

	return pResult;
}

PPBElement CreateStructElement
(
	_In_ PPBElement* pElementList,
	_In_ DWORD dwCount,
	_In_ DWORD dwFieldIdx
)
{
	PPBElement pResult = NULL;
	DWORD i = 0;
	PBYTE pMarshalledFieldIdx = NULL;
	DWORD cbMarshalledFieldIdx = 0;
	DWORD dwPos = 0;
	DWORD dwTemp = dwCount;

	pResult = ALLOC(sizeof(PBElement));
	pResult->Type = Repeated;
	pResult->dwNumberOfSubElement = dwCount;
	pResult->SubElements = ALLOC(dwCount * sizeof(PBElement));
	for (i = 0; i < dwTemp; i++) {
		if (pElementList[i] == NULL) {
			dwCount--;
			continue;
		}

		pResult->SubElements[i - (dwTemp - dwCount)] = pElementList[i];
		pResult->cbMarshalledData += pElementList[i]->cbMarshalledData;
	}

	if (dwFieldIdx > 0) {
		pMarshalledFieldIdx = MarshalVarInt(dwFieldIdx, &cbMarshalledFieldIdx);
	}

	pResult->pMarshalledData = ALLOC(pResult->cbMarshalledData + cbMarshalledFieldIdx);
	if (pMarshalledFieldIdx != NULL) {
		memcpy(pResult->pMarshalledData, pMarshalledFieldIdx, cbMarshalledFieldIdx);
		dwPos += cbMarshalledFieldIdx;
		FREE(pMarshalledFieldIdx);
	}

	for (i = 0; i < dwCount; i++) {
		memcpy(&pResult->pMarshalledData[dwPos], pResult->SubElements[i]->pMarshalledData, pResult->SubElements[i]->cbMarshalledData);
		dwPos += pResult->SubElements[i]->cbMarshalledData;
	}

	return pResult;
}

VOID FreeElement
(
	_In_ PPBElement pElement
)
{
	DWORD i = 0;

	if (pElement == NULL) {
		return;
	}

	if ((pElement == Repeated || pElement == StructType) && pElement->SubElements != NULL) {
		for (i = 0; i < pElement->dwNumberOfSubElement; i++) {
			if (pElement->SubElements[i] != NULL) {
				FreeElement(pElement->SubElements[i]);
			}
		}

		FREE(pElement->SubElements);
	}

	FREE(pElement->pMarshalledData);
	FREE(pElement);
}