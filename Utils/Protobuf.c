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

VOID FreeBufferList
(
	_In_ PBUFFER* BufferList,
	_In_ DWORD dwNumberOfBuffers
)
{
	DWORD i = 0;

	if (BufferList != NULL) {
		for (i = 0; i < dwNumberOfBuffers; i++) {
			FreeBuffer(BufferList[i]);
		}

		FREE(BufferList);
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
	PBYTE pMarshaledFieldIdx = NULL;
	DWORD cbMarshaledFieldIdx = 0;

	if (pData == NULL || cbData == 0) {
		return NULL;
	}

	pResult = ALLOC(sizeof(PBElement));
	pResult->Type = Bytes;
	pMarshaledFieldIdx = MarshalVarInt((dwFieldIdx << 3) | 2, &cbMarshaledFieldIdx);
	pDataSize = MarshalVarInt(cbData, &cbDataSize);
	pResult->cbMarshaledData = cbDataSize + cbData + cbMarshaledFieldIdx;
	pResult->pMarshaledData = ALLOC(pResult->cbMarshaledData);
	memcpy(pResult->pMarshaledData, pMarshaledFieldIdx, cbMarshaledFieldIdx);
	FREE(pMarshaledFieldIdx);
	memcpy(&pResult->pMarshaledData[cbMarshaledFieldIdx], pDataSize, cbDataSize);
	FREE(pDataSize);
	memcpy(&pResult->pMarshaledData[cbDataSize + cbMarshaledFieldIdx], pData, cbData);
	return pResult;
}

PPBElement CreateVarIntElement
(
	_In_ UINT64 uValue,
	_In_ DWORD dwFieldIdx
)
{
	PPBElement pResult = NULL;
	PBYTE pMarshaledFieldIdx = NULL;
	DWORD cbMarshaledFieldIdx = 0;
	PBYTE pMarshaledData = NULL;
	DWORD cbMarshaledData = 0;

	pResult = ALLOC(sizeof(PBElement));
	pResult->Type = Varint;
	pMarshaledFieldIdx = MarshalVarInt(dwFieldIdx << 3, &cbMarshaledFieldIdx);
	pMarshaledData = MarshalVarInt(uValue, &cbMarshaledData);
	pResult->cbMarshaledData = cbMarshaledData + cbMarshaledFieldIdx;
	pResult->pMarshaledData = ALLOC(pResult->cbMarshaledData);
	memcpy(pResult->pMarshaledData, pMarshaledFieldIdx, cbMarshaledFieldIdx);
	memcpy(pResult->pMarshaledData + cbMarshaledFieldIdx, pMarshaledData, cbMarshaledData);
	FREE(pMarshaledData);
	FREE(pMarshaledFieldIdx);

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
	DWORD cbMarshaledOutput = 0;
	PBYTE pMarshaledFieldIdx = NULL;
	DWORD cbMarshaledFieldIdx = 0;
	DWORD dwPos = 0;

	pResult = ALLOC(sizeof(PBElement));
	pMarshaledFieldIdx = MarshalVarInt((dwFieldIdx << 3) | 2, &cbMarshaledFieldIdx);
	cbMarshaledOutput += cbMarshaledFieldIdx;
	for (i = 0; i < dwNumberOfEntries; i++) {
		dwTemp = 0;
		pTemp = MarshalVarInt(pIntList[i], &dwTemp);
		FREE(pTemp);
		cbMarshaledOutput += dwTemp;
	}

	pResult->cbMarshaledData = cbMarshaledOutput;
	pResult->pMarshaledData = ALLOC(cbMarshaledOutput);
	memcpy(&pResult->pMarshaledData[dwPos], pMarshaledFieldIdx, cbMarshaledFieldIdx);
	dwPos += cbMarshaledFieldIdx;
	for (i = 0; i < dwNumberOfEntries; i++) {
		dwTemp = 0;
		pTemp = MarshalVarInt(pIntList[i], &dwTemp);
		memcpy(&pResult->pMarshaledData[dwPos], pTemp, dwTemp);
		dwPos += dwTemp;
		FREE(pTemp);
	}

	pResult->Type = RepeatedVarint;
	FREE(pMarshaledFieldIdx);
	return pResult;
}

PPBElement CreateRepeatedBytesElement
(
	_In_ PBUFFER* pArrayOfBytes,
	_In_ DWORD dwNumberOfBuffers,
	_In_ DWORD dwFieldIdx
)
{
	PPBElement pResult = NULL;
	DWORD i = 0;
	DWORD j = 0;
	DWORD dwTemp = 0;
	PBYTE pTemp = NULL;
	DWORD cbMarshaledOutput = 0;
	PBYTE pMarshaledFieldIdx = NULL;
	DWORD cbMarshaledFieldIdx = 0;
	DWORD dwPos = 0;
	PBUFFER* pBufferList = NULL;

	pBufferList = ALLOC(sizeof(PBUFFER) * dwNumberOfBuffers);
	for (i = 0; i < dwNumberOfBuffers; i++) {
		if (pArrayOfBytes[i] != NULL) {
			pBufferList[j] = pArrayOfBytes[i];
			j++;
		}
	}

	dwNumberOfBuffers = j;
	if (dwNumberOfBuffers == 0) {
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(PBElement));
	pMarshaledFieldIdx = MarshalVarInt((dwFieldIdx << 3) | 2, &cbMarshaledFieldIdx);
	for (i = 0; i < dwNumberOfBuffers; i++) {
		cbMarshaledOutput += cbMarshaledFieldIdx;
		cbMarshaledOutput += pBufferList[i]->cbBuffer;
		dwTemp = 0;
		pTemp = MarshalVarInt(pBufferList[i]->cbBuffer, &dwTemp);
		FREE(pTemp);
		cbMarshaledOutput += dwTemp;
	}

	pResult->cbMarshaledData = cbMarshaledOutput;
	pResult->pMarshaledData = ALLOC(cbMarshaledOutput);
	for (i = 0; i < dwNumberOfBuffers; i++) {
		memcpy(&pResult->pMarshaledData[dwPos], pMarshaledFieldIdx, cbMarshaledFieldIdx);
		dwPos += cbMarshaledFieldIdx;
		dwTemp = 0;
		pTemp = MarshalVarInt(pBufferList[i]->cbBuffer, &dwTemp);
		memcpy(&pResult->pMarshaledData[dwPos], pTemp, dwTemp);
		dwPos += dwTemp;
		FREE(pTemp);
		memcpy(&pResult->pMarshaledData[dwPos], pBufferList[i]->pBuffer, pBufferList[i]->cbBuffer);
		dwPos += pBufferList[i]->cbBuffer;
	}

	pResult->Type = RepeatedBytes;

CLEANUP:
	FREE(pMarshaledFieldIdx);
	FREE(pBufferList);

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
	pResult->cbMarshaledData = 0x400;
	pResult->pMarshaledData = ALLOC(pResult->cbMarshaledData);
	dwFieldIdx <<= 3;
	dwFieldIdx |= 2;
	pMashalledFieldIdx = MarshalVarInt(dwFieldIdx, &cbMashalledFieldIdx);
	for (i = 0; i < cElementList; i++) {
		if (dwPos + pResult->SubElements[i]->cbMarshaledData + 0x12 >= pResult->cbMarshaledData) {
			pResult->cbMarshaledData = 2 * (dwPos + pResult->SubElements[i]->cbMarshaledData + 0x12);
			pResult->pMarshaledData = REALLOC(pResult->pMarshaledData, pResult->cbMarshaledData);
		}

		memcpy(&pResult->pMarshaledData[dwPos], pMashalledFieldIdx, cbMashalledFieldIdx);
		dwPos += cbMashalledFieldIdx;
		pMashalledSize = MarshalVarInt(pResult->SubElements[i]->cbMarshaledData, &cbMashalledSize);
		memcpy(&pResult->pMarshaledData[dwPos], pMashalledSize, cbMashalledSize);
		dwPos += cbMashalledSize;
		FREE(pMashalledSize);
		memcpy(&pResult->pMarshaledData[dwPos], pResult->SubElements[i]->pMarshaledData, pResult->SubElements[i]->cbMarshaledData);
		dwPos += pResult->SubElements[i]->cbMarshaledData;
	}

	pResult->cbMarshaledData = dwPos;
	pResult->pMarshaledData = REALLOC(pResult->pMarshaledData, dwPos);
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
	PBYTE pMarshaledData = NULL;
	DWORD cbMarshaledSize = 0;
	DWORD dwPos = 0;
	DWORD dwTemp = dwCount;

	pResult = ALLOC(sizeof(PBElement));
	pResult->Type = StructType;
	pResult->dwNumberOfSubElement = dwCount;
	if (pElementList != NULL && dwCount > 0) {
		pResult->SubElements = ALLOC(dwCount * sizeof(PBElement));
		for (i = 0; i < dwTemp; i++) {
			if (pElementList[i] == NULL) {
				dwCount--;
				continue;
			}

			pResult->SubElements[i - (dwTemp - dwCount)] = pElementList[i];
			pResult->cbMarshaledData += pElementList[i]->cbMarshaledData;
		}
	}

	if (dwFieldIdx > 0) {
		dwFieldIdx <<= 3;
		dwFieldIdx |= 2;
		pMarshaledData = MarshalVarInt(dwFieldIdx, &cbMarshaledSize);
	}

	if (pElementList == NULL || dwCount == 0) {
		if (dwFieldIdx > 0) {
			pResult->cbMarshaledData = cbMarshaledSize + 1;
			pResult->pMarshaledData = ALLOC(pResult->cbMarshaledData);
			memcpy(pResult->pMarshaledData, pMarshaledData, cbMarshaledSize);
		}
		
		return pResult;
	}

	pResult->pMarshaledData = ALLOC(pResult->cbMarshaledData + 0x20);
	if (pMarshaledData != NULL) {
		memcpy(pResult->pMarshaledData, pMarshaledData, cbMarshaledSize);
		dwPos += cbMarshaledSize;
		FREE(pMarshaledData);
		pResult->cbMarshaledData += cbMarshaledSize;
		pMarshaledData = MarshalVarInt(pResult->cbMarshaledData - cbMarshaledSize, &cbMarshaledSize);
		memcpy(pResult->pMarshaledData + dwPos, pMarshaledData, cbMarshaledSize);
		pResult->cbMarshaledData += cbMarshaledSize;
		dwPos += cbMarshaledSize;
		FREE(pMarshaledData);
		pResult->pMarshaledData = REALLOC(pResult->pMarshaledData, pResult->cbMarshaledData);
	}

	for (i = 0; i < dwCount; i++) {
		memcpy(&pResult->pMarshaledData[dwPos], pResult->SubElements[i]->pMarshaledData, pResult->SubElements[i]->cbMarshaledData);
		dwPos += pResult->SubElements[i]->cbMarshaledData;
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

	FREE(pElement->pMarshaledData);
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
	DWORD cbMarshaledFieldIdx = 0;
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
		uFieldIdx = UnmarshalVarInt(pInput + dwPos, &cbMarshaledFieldIdx);
		uFieldIdx >>= 3;
		if (uFieldIdx != pElement->dwFieldIdx) {
			break;
		}

		dwPos += cbMarshaledFieldIdx;
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
	DWORD cbMarshaledData = 0;
	DWORD dwTemp = 0;
	DWORD i = 0;
	DWORD dwPos = 0;
	DWORD dwNumberOfEntries = 0x10;
	PUINT64 pResult = NULL;

	cbMarshaledData = UnmarshalVarInt(pInput, &dwTemp);
	if (pdwNumberOfBytesRead != NULL) {
		*pdwNumberOfBytesRead = dwTemp + cbMarshaledData;
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
		if (dwPos >= cbMarshaledData) {
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