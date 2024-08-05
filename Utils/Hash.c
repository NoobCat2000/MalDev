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