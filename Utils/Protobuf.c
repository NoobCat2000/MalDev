#include "pch.h"

VOID FreeBuffer
(
	_In_ PBUFFER pBuffer
)
{
	if (pBuffer != NULL) {
		FREE(pBuffer->pBuffer);
		FREE(pBuffer);
	}
}

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

	if (uValue == 0) {
		pResult = ALLOC(1);
		if (pcbOutput != NULL) {
			*pcbOutput = 1;
		}

		return pResult;
	}

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

UINT64 UnmarshalVarInt
(
	_In_ PBYTE pInput,
	_Out_opt_ PDWORD pNumberOfBytesRead
)
{
	INT64 i = 0;
	UINT64 uResult = 0;
	DWORD dwMaxLoop = 0;
	
	while (TRUE) {
		/*uResult <<= 7;
		uResult |= (pInput[i] & 0x7F);*/
		if (!(pInput[dwMaxLoop++] & 0x80)) {
			break;
		}
	}

	for (i = dwMaxLoop - 1; i >= 0; i--) {
		uResult <<= 7;
		uResult |= (pInput[i] & 0x7F);
	}

	if (pNumberOfBytesRead != NULL) {
		*pNumberOfBytesRead = dwMaxLoop;
	}
	
	return uResult;
}

PBUFFER UnmarshalBytes
(
	_In_ PBYTE pInput,
	_Out_ PDWORD pNumberOfBytesRead
)
{
	DWORD i = 0;
	UINT64 cbResult = 0;
	PBUFFER pResult = NULL;
	DWORD dwNumberOfBytesRead = 0;

	cbResult = UnmarshalVarInt(pInput, &dwNumberOfBytesRead);
	pResult = ALLOC(sizeof(BUFFER));
	pResult->pBuffer = ALLOC(cbResult + 1);
	pResult->cbBuffer = cbResult;
	memcpy(pResult->pBuffer, pInput + dwNumberOfBytesRead, cbResult);
	if (pNumberOfBytesRead != NULL) {
		*pNumberOfBytesRead = cbResult + dwNumberOfBytesRead;
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
	pResult->Type = Bytes;
	pMarshalledFieldIdx = MarshalVarInt((dwFieldIdx << 3) | 2, &cbMarshalledFieldIdx);
	pDataSize = MarshalVarInt(cbData, &cbDataSize);
	pResult->cbMarshalledData = cbDataSize + cbData + cbMarshalledFieldIdx;
	pResult->pMarshalledData = ALLOC(pResult->cbMarshalledData);
	memcpy(pResult->pMarshalledData, pMarshalledFieldIdx, cbMarshalledFieldIdx);
	FREE(pMarshalledFieldIdx);
	memcpy(&pResult->pMarshalledData[cbMarshalledFieldIdx], pDataSize, cbDataSize);
	FREE(pDataSize);
	memcpy(&pResult->pMarshalledData[cbDataSize + cbMarshalledFieldIdx], pData, cbData);
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
	pMarshalledFieldIdx = MarshalVarInt(dwFieldIdx << 3, &cbMarshalledFieldIdx);
	pMarshalledData = MarshalVarInt(uValue, &cbMarshalledData);
	pResult->cbMarshalledData = cbMarshalledData + cbMarshalledFieldIdx;
	pResult->pMarshalledData = ALLOC(pResult->cbMarshalledData);
	memcpy(pResult->pMarshalledData, pMarshalledFieldIdx, cbMarshalledFieldIdx);
	memcpy(pResult->pMarshalledData + cbMarshalledFieldIdx, pMarshalledData, cbMarshalledData);
	FREE(pMarshalledData);
	FREE(pMarshalledFieldIdx);

	return pResult;
}

PPBElement CreateRepeatedVarIntElement
(
	_In_ PUINT64 pIntList,
	_In_ DWORD dwNumberOfEntries,
	_In_ DWORD dwFieldIdx
)
{
	PPBElement pResult = NULL;
	DWORD i = 0;
	DWORD dwTemp = 0;
	PBYTE pTemp = NULL;
	DWORD cbMarshalledOutput = 0;
	PBYTE pMarshalledFieldIdx = NULL;
	DWORD cbMarshalledFieldIdx = 0;
	DWORD dwPos = 0;

	pResult = ALLOC(sizeof(PBElement));
	pMarshalledFieldIdx = MarshalVarInt((dwFieldIdx << 3) | 2, &cbMarshalledFieldIdx);
	cbMarshalledOutput += cbMarshalledFieldIdx;
	for (i = 0; i < dwNumberOfEntries; i++) {
		dwTemp = 0;
		pTemp = MarshalVarInt(pIntList[i], &dwTemp);
		FREE(pTemp);
		cbMarshalledOutput += dwTemp;
	}

	pResult->cbMarshalledData = cbMarshalledOutput;
	pResult->pMarshalledData = ALLOC(cbMarshalledOutput);
	memcpy(&pResult->pMarshalledData[dwPos], pMarshalledFieldIdx, cbMarshalledFieldIdx);
	dwPos += cbMarshalledFieldIdx;
	for (i = 0; i < dwNumberOfEntries; i++) {
		dwTemp = 0;
		pTemp = MarshalVarInt(pIntList[i], &dwTemp);
		memcpy(&pResult->pMarshalledData[dwPos], pTemp, dwTemp);
		dwPos += dwTemp;
		FREE(pTemp);
	}

	pResult->Type = RepeatedVarint;
	FREE(pMarshalledFieldIdx);
	return pResult;
}

PPBElement CreateRepeatedBytesElement
(
	_In_ PBUFFER* pArrayOfBytes,
	_In_ DWORD dwNumberOfEntries,
	_In_ DWORD dwFieldIdx
)
{
	PPBElement pResult = NULL;
	DWORD i = 0;
	DWORD dwTemp = 0;
	PBYTE pTemp = NULL;
	DWORD cbMarshalledOutput = 0;
	PBYTE pMarshalledFieldIdx = NULL;
	DWORD cbMarshalledFieldIdx = 0;
	DWORD dwPos = 0;

	pResult = ALLOC(sizeof(PBElement));
	pMarshalledFieldIdx = MarshalVarInt((dwFieldIdx << 3) | 2, &cbMarshalledFieldIdx);
	for (i = 0; i < dwNumberOfEntries; i++) {
		cbMarshalledOutput += cbMarshalledFieldIdx;
		cbMarshalledOutput += pArrayOfBytes[i]->cbBuffer;
		dwTemp = 0;
		pTemp = MarshalVarInt(pArrayOfBytes[i]->cbBuffer, &dwTemp);
		FREE(pTemp);
		cbMarshalledOutput += dwTemp;
	}

	pResult->cbMarshalledData = cbMarshalledOutput;
	pResult->pMarshalledData = ALLOC(cbMarshalledOutput);
	for (i = 0; i < dwNumberOfEntries; i++) {
		memcpy(&pResult->pMarshalledData[dwPos], pMarshalledFieldIdx, cbMarshalledFieldIdx);
		dwPos += cbMarshalledFieldIdx;
		dwTemp = 0;
		pTemp = MarshalVarInt(pArrayOfBytes[i]->cbBuffer, &dwTemp);
		memcpy(&pResult->pMarshalledData[dwPos], pTemp, dwTemp);
		dwPos += dwTemp;
		FREE(pTemp);
		memcpy(&pResult->pMarshalledData[dwPos], pArrayOfBytes[i]->pBuffer, pArrayOfBytes[i]->cbBuffer);
		dwPos += pArrayOfBytes[i]->cbBuffer;
	}

	pResult->Type = RepeatedBytes;
	FREE(pMarshalledFieldIdx);
	return pResult;
}

PPBElement CreateRepeatedStructElement
(
	_In_ PPBElement* pElementList,
	_In_ DWORD cElementList,
	_In_ DWORD dwFieldIdx
)
{
	PPBElement pResult = NULL;
	DWORD cbMashalledSize = 0;
	PBYTE pMashalledSize = NULL;
	DWORD cbMashalledFieldIdx = 0;
	PBYTE pMashalledFieldIdx = NULL;
	DWORD i = 0;
	DWORD dwPos = 0;
	DWORD dwTemp = cElementList;

	if (dwFieldIdx == 0) {
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(PBElement));
	pResult->SubElements = ALLOC(sizeof(PPBElement) * cElementList);
	for (i = 0; i < dwTemp; i++) {
		if (pElementList[i] == NULL) {
			cElementList--;
			continue;
		}

		pResult->SubElements[i - (dwTemp - cElementList)] = pElementList[i];
	}

	pResult->Type = RepeatedStruct;
	pResult->cbMarshalledData = 0x400;
	pResult->pMarshalledData = ALLOC(pResult->cbMarshalledData);
	dwFieldIdx <<= 3;
	dwFieldIdx |= 2;
	pMashalledFieldIdx = MarshalVarInt(dwFieldIdx, &cbMashalledFieldIdx);
	for (i = 0; i < cElementList; i++) {
		if (dwPos + pResult->SubElements[i]->cbMarshalledData + 0x12 >= pResult->cbMarshalledData) {
			pResult->cbMarshalledData = 2 * (dwPos + pResult->SubElements[i]->cbMarshalledData + 0x12);
			pResult->pMarshalledData = REALLOC(pResult->pMarshalledData, pResult->cbMarshalledData);
		}

		memcpy(&pResult->pMarshalledData[dwPos], pMashalledFieldIdx, cbMashalledFieldIdx);
		dwPos += cbMashalledFieldIdx;
		pMashalledSize = MarshalVarInt(pResult->SubElements[i]->cbMarshalledData, &cbMashalledSize);
		memcpy(&pResult->pMarshalledData[dwPos], pMashalledSize, cbMashalledSize);
		dwPos += cbMashalledSize;
		FREE(pMashalledSize);
		memcpy(&pResult->pMarshalledData[dwPos], pResult->SubElements[i]->pMarshalledData, pResult->SubElements[i]->cbMarshalledData);
		dwPos += pResult->SubElements[i]->cbMarshalledData;
	}

	pResult->cbMarshalledData = dwPos;
	pResult->pMarshalledData = REALLOC(pResult->pMarshalledData, dwPos);
CLEANUP:
	FREE(pMashalledFieldIdx);

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
	PBYTE pMarshalledData = NULL;
	DWORD cbMarshalledSize = 0;
	DWORD dwPos = 0;
	DWORD dwTemp = dwCount;

	pResult = ALLOC(sizeof(PBElement));
	pResult->Type = StructType;
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
		dwFieldIdx <<= 3;
		dwFieldIdx |= 2;
		pMarshalledData = MarshalVarInt(dwFieldIdx, &cbMarshalledSize);
	}

	pResult->pMarshalledData = ALLOC(pResult->cbMarshalledData + 0x20);
	if (pMarshalledData != NULL) {
		memcpy(pResult->pMarshalledData, pMarshalledData, cbMarshalledSize);
		dwPos += cbMarshalledSize;
		FREE(pMarshalledData);
		pResult->cbMarshalledData += cbMarshalledSize;
		pMarshalledData = MarshalVarInt(pResult->cbMarshalledData - cbMarshalledSize, &cbMarshalledSize);
		memcpy(pResult->pMarshalledData + dwPos, pMarshalledData, cbMarshalledSize);
		pResult->cbMarshalledData += cbMarshalledSize;
		dwPos += cbMarshalledSize;
		FREE(pMarshalledData);
		pResult->pMarshalledData = REALLOC(pResult->pMarshalledData, pResult->cbMarshalledData);
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

	if ((pElement == StructType) && pElement->SubElements != NULL) {
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

PBUFFER* UnmarshalRepeatedBytes
(
	_In_ PPBElement pElement,
	_In_ PBYTE pInput,
	_Out_ PDWORD pdwNumberOfBytesRead
)
{
	DWORD cbOutput = 0;
	UINT64 uFieldIdx = 0;
	DWORD cbMarshalledFieldIdx = 0;
	PBUFFER* pResult = NULL;
	DWORD dwNumberOfEntries = 0x10;
	DWORD i = 0;
	DWORD cbData = 0;
	DWORD dwTemp = 0;
	PBYTE pData = NULL;
	DWORD dwPos = 0;

	pResult = ALLOC(sizeof(PBUFFER) * dwNumberOfEntries);
	i++;
	while (TRUE) {
		uFieldIdx = UnmarshalVarInt(pInput + dwPos, &cbMarshalledFieldIdx);
		uFieldIdx >>= 3;
		if (uFieldIdx != pElement->dwFieldIdx) {
			break;
		}

		dwPos += cbMarshalledFieldIdx;
		cbData = UnmarshalVarInt(pInput + dwPos, &dwTemp);
		dwPos += dwTemp;
		pResult[i] = ALLOC(sizeof(BUFFER));
		pResult[i]->pBuffer = ALLOC(cbData + 1);
		pResult[i]->cbBuffer = cbData;
		memcpy(pResult[i]->pBuffer, pInput + dwPos, cbData);
		dwPos += cbData;
		if (++i >= dwNumberOfEntries) {
			dwNumberOfEntries *= 2;
			pResult = REALLOC(pResult, dwNumberOfEntries * sizeof(PBUFFER));
		}
	}

	if (pdwNumberOfBytesRead != NULL) {
		*pdwNumberOfBytesRead = dwPos;
	}

	pResult = REALLOC(pResult, i * sizeof(PBUFFER));
	*((PDWORD)pResult) = i - 1;
	return pResult;
}

PUINT64 UnmarshalRepeatedVarInt
(
	_In_ PBYTE pInput,
	_Out_ PDWORD pdwNumberOfBytesRead
)
{
	DWORD cbMarshalledData = 0;
	DWORD dwTemp = 0;
	DWORD i = 0;
	DWORD dwPos = 0;
	DWORD dwNumberOfEntries = 0x10;
	PUINT64 pResult = NULL;

	cbMarshalledData = UnmarshalVarInt(pInput, &dwTemp);
	if (pdwNumberOfBytesRead != NULL) {
		*pdwNumberOfBytesRead = dwTemp + cbMarshalledData;
	}

	dwPos += dwTemp;
	pResult = ALLOC(sizeof(UINT64) * dwNumberOfEntries);
	i++;
	while (TRUE) {
		dwTemp = 0;
		pResult[i++] = UnmarshalVarInt(pInput + dwPos, &dwTemp);
		if (i >= dwNumberOfEntries) {
			dwNumberOfEntries *= 2;
			pResult = REALLOC(pResult, sizeof(UINT64) * dwNumberOfEntries);
		}

		dwPos += dwTemp;
		if (dwPos >= cbMarshalledData) {
			break;
		}
	}

	pResult = REALLOC(pResult, sizeof(UINT64) * i);
	pResult[0] = i - 1;
	return pResult;
}

LPVOID* UnmarshalStruct
(
	_In_ PPBElement* pElementList,
	_In_ DWORD dwNumberOfEntries,
	_In_ PBYTE pInput,
	_In_ DWORD cbInput,
	_Out_opt_ PDWORD pNumberOfBytesRead
)
{
	DWORD dwFieldIdx = 0;
	DWORD dwStructSize = 0;
	DWORD dwTemp = 0;
	DWORD i = 0;
	DWORD dwPos = 0;
	LPVOID* pResult = NULL;

	pResult = ALLOC(sizeof(LPVOID) * dwNumberOfEntries);
	for (i = 0; i < dwNumberOfEntries; i++) {
		if (dwPos >= cbInput) {
			break;
		}

		if (pElementList[i] == NULL) {
			continue;
		}

		dwFieldIdx = UnmarshalVarInt(pInput + dwPos, &dwTemp);
		dwFieldIdx >>= 3;
		if (dwFieldIdx != pElementList[i]->dwFieldIdx) {
			continue;
		}

		if (pElementList[i]->Type == Varint) {
			dwPos += dwTemp;
			pResult[i] = (LPVOID)UnmarshalVarInt(pInput + dwPos, &dwTemp);
			dwPos += dwTemp;
		}
		else if (pElementList[i]->Type == Bytes) {
			dwPos += dwTemp;
			pResult[i] = UnmarshalBytes(pInput + dwPos, &dwTemp);
			dwPos += dwTemp;
		}
		else if (pElementList[i]->Type == RepeatedVarint) {
			dwPos += dwTemp;
			pResult[i] = UnmarshalRepeatedVarInt(pInput + dwPos, &dwTemp);
			dwPos += dwTemp;
		}
		else if (pElementList[i]->Type == RepeatedBytes) {
			pResult[i] = UnmarshalRepeatedBytes(pElementList[i], pInput + dwPos, &dwTemp);
			dwPos += dwTemp;
		}
		else if (pElementList[i]->Type == StructType) {
			dwPos += dwTemp;
			dwStructSize = UnmarshalVarInt(pInput + dwPos, &dwTemp);
			dwPos += dwTemp;
			pResult[i] = UnmarshalStruct(pElementList[i]->SubElements, pElementList[i]->dwNumberOfSubElement, pInput + dwPos, dwStructSize, &dwTemp);
			dwPos += dwTemp;
		}
		else if (pElementList[i]->Type == RepeatedStruct) {

		}
	}

	if (pNumberOfBytesRead != NULL) {
		*pNumberOfBytesRead = dwPos;
	}

	if (dwPos == 0) {
		FREE(pResult);
		pResult = NULL;
	}

	return pResult;
}



//VOID UnmarshalProtobuf
//(
//	_In_ PBYTE pInput,
//	_In_ DWORD cbInput,
//	_In_ PDWORD pFieldIdxArray,
//	_In_ DWORD dwNumberOfFieldIdxs,
//	_Out_ PBYTE* pOutput,
//	_Out_ PDWORD pcbOutput
//)
//{
//	PBYTE pResult = NULL;
//	DWORD i = 0;
//	DWORD dwFieldIdx = 0;
//	DWORD dwType = 0;
//	DWORD dwNumberOfBytesRead = 0;
//	DWORD dwPos = 0;
//
//	pResult = ALLOC(dwNumberOfFieldIdxs * sizeof(LPVOID));
//	for (i = 0; i < dwNumberOfFieldIdxs; i++) {
//		dwNumberOfBytesRead = 0;
//		dwFieldIdx = UnmarshalVarInt(pInput + dwPos, &dwNumberOfBytesRead);
//		dwType = dwFieldIdx & 0x7;
//		dwFieldIdx >>= 3;
//		if (dwFieldIdx == pFieldIdxArray[i]) {
//			continue;
//		}
//
//		dwPos += dwNumberOfBytesRead;
//		if (dwType == Varint) {
//
//		}
//		else if (dwType == LengthDelimited) {
//
//		}
//		else {
//			FREE(pResult);
//			pResult = NULL;
//			goto CLEANUP;
//		}
//	}
//
//CLEANUP:
//	return pResult;
//}