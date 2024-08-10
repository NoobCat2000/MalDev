#include "pch.h"

PBYTE ComputeHash
(
	_In_ PBYTE pbData,
	_In_ DWORD dwDataLen,
	_In_ LPSTR lpAlgId
)
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
	PBYTE pbHash = NULL, pbHashObject = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	Status = BCryptOpenAlgorithmProvider(&hAlg, lpAlgId, NULL, 0);
	if (!NT_SUCCESS(Status))
	{
		goto CLEANUP;
	}

	Status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
	if (!NT_SUCCESS(Status))
	{
		goto CLEANUP;
	}

	pbHashObject = ALLOC(cbHashObject + 1);
	if (NULL == pbHashObject)
	{
		goto CLEANUP;
	}

	Status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
	if (!NT_SUCCESS(Status))
	{
		goto CLEANUP;
	}

	pbHash = ALLOC(cbHash + 1);
	if (NULL == pbHash)
	{
		goto CLEANUP;
	}

	Status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
	if (!NT_SUCCESS(Status))
	{
		goto CLEANUP;
	}

	Status = BCryptHashData(hHash, pbData, dwDataLen, 0);
	if (!NT_SUCCESS(Status))
	{
		goto CLEANUP;
	}

	Status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
	if (!NT_SUCCESS(Status))
	{
		goto CLEANUP;
	}

CLEANUP:
	if (pbHashObject != NULL) {
		FREE(pbHashObject);
	}

	return pbHash;
}

PBYTE ComputeSHA256
(
	_In_ PBYTE pbData,
	_In_ DWORD dwDataLen
)
{
	return ComputeHash(pbData, dwDataLen, BCRYPT_SHA256_ALGORITHM);
}

PBYTE HKDFExtract
(
	_In_ PBYTE pSalt,
	_In_ DWORD cbSalt,
	_In_ PBYTE pIKM,
	_In_ DWORD cbIKM
)
{
	BOOL IsSaltNull = FALSE;
	PBYTE pResult = NULL;

	if (cbSalt == 0 && pSalt == NULL) {
		pSalt = ALLOC(SHA256_HASH_SIZE);
		cbSalt = SHA256_HASH_SIZE;
		IsSaltNull = TRUE;
	}

	pResult = GenerateHmacSHA256(pSalt, cbSalt, pIKM, cbIKM);
	if (IsSaltNull && pSalt != NULL) {
		FREE(pSalt);
	}

	return pResult;
}

PBYTE HKDFExpand
(
	_In_ PBYTE pPseudoRandKey,
	_In_ DWORD cbPseudoRandKey,
	_In_ PBYTE pInfo,
	_In_ DWORD cbInfo,
	_In_ DWORD cbDerivedKey
)
{
	PBYTE pReturnedHMAC = NULL;
	PBYTE pTemp = NULL;
	DWORD cbTemp = NULL;
	PBYTE pResult = NULL;
	DWORD dwCounter = 0;
	DWORD dwIdx = 0;

	pTemp = ALLOC(SHA256_HASH_SIZE + cbInfo + 1);
	pResult = ALLOC(cbDerivedKey - (cbDerivedKey % SHA256_HASH_SIZE) + SHA256_HASH_SIZE);
	while (dwIdx < cbDerivedKey) {
		cbTemp = 0;
		if (pReturnedHMAC != NULL) {
			memcpy(pTemp + cbTemp, pReturnedHMAC, SHA256_HASH_SIZE);
			cbTemp += SHA256_HASH_SIZE;
			FREE(pReturnedHMAC);
			pReturnedHMAC = NULL;
		}

		dwCounter++;
		if (pInfo != NULL && cbInfo > 0) {
			memcpy(pTemp + cbTemp, pInfo, cbInfo);
			cbTemp += cbInfo;
		}
		
		memcpy(pTemp + cbTemp, &dwCounter, 1);
		cbTemp += 1;
		pReturnedHMAC = GenerateHmacSHA256(pPseudoRandKey, cbPseudoRandKey, pTemp, cbTemp);
		if (pReturnedHMAC == NULL) {
			goto CLEANUP;
		}

		memcpy(pResult + dwIdx, pReturnedHMAC, SHA256_HASH_SIZE);
		dwIdx += SHA256_HASH_SIZE;
	}

CLEANUP:
	if (pTemp != NULL) {
		FREE(pTemp);
	}

	if (pReturnedHMAC != NULL) {
		FREE(pReturnedHMAC);
	}

	return pResult;
}

PBYTE HKDFGenerate
(
	_In_ PBYTE pSalt,
	_In_ DWORD cbSalt,
	_In_ PBYTE pIKM,
	_In_ DWORD cbIKM,
	_In_ PBYTE pInfo,
	_In_ DWORD cbInfo,
	_In_ DWORD cbDerivedKey
)
{
	PBYTE pPseudoRandKey = NULL;
	PBYTE pResult = NULL;

	pPseudoRandKey = HKDFExtract(pSalt, cbSalt, pIKM, cbIKM);
	if (pPseudoRandKey == NULL) {
		return NULL;
	}
	
	pResult = HKDFExpand(pPseudoRandKey, SHA256_HASH_SIZE, pInfo, cbInfo, cbDerivedKey);
	if (pPseudoRandKey != NULL) {
		FREE(pPseudoRandKey);
	}

	return pResult;
}