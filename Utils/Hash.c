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

PBYTE ComputeSHA512
(
	_In_ PBYTE pbData,
	_In_ DWORD dwDataLen
)
{
	return ComputeHash(pbData, dwDataLen, BCRYPT_SHA512_ALGORITHM);
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

VOID G
(
	_In_ PUINT64 v,
	_In_ DWORD a,
	_In_ DWORD b,
	_In_ DWORD c,
	_In_ DWORD d,
	_In_ INT64 x,
	_In_ INT64 y
)
{
	v[a] = v[a] + v[b] + x;
	v[d] = ROTR64(v[d] ^ v[a], 32);

	v[c] = v[c] + v[d];
	v[b] = ROTR64(v[b] ^ v[c], 24);

	v[a] = v[a] + v[b] + y;
	v[d] = ROTR64(v[d] ^ v[a], 16);

	v[c] = v[c] + v[d];
	v[b] = ROTR64(v[b] ^ v[c], 63);
}

VOID F
(
	_In_ PBLAKE2B_STATE pState,
	_In_ PUINT64 pBlock
)
{
	DWORD i, j;
	UINT64 v[16], m[16], s[16];
	UINT64 Blake2bIV[8] = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };
	UINT8 Blake2bSigma[12][16] = {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
  { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
  { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
  { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
  { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
	};

	for (i = 0; i < 16; ++i) {
		m[i] = pBlock[i];
	}

	for (i = 0; i < 8; ++i) {
		v[i] = pState->h[i];
		v[i + 8] = Blake2bIV[i];
	}

	v[12] ^= pState->t[0];
	v[13] ^= pState->t[1];
	v[14] ^= pState->f[0];
	v[15] ^= pState->f[1];

	for (i = 0; i < 12; i++) {
		for (j = 0; j < 16; j++) {
			s[j] = Blake2bSigma[i][j];
		}

		G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
		G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
		G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
		G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
		G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
		G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
		G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
		G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
	}

	for (i = 0; i < 8; i++) {
		pState->h[i] = pState->h[i] ^ v[i] ^ v[i + 8];
	}
}

VOID Blake2BIncrementCounter
(
	_In_ PBLAKE2B_STATE pState,
	_In_ UINT64 uInc
)
{
	pState->t[0] += uInc;
	pState->t[1] += (pState->t[0] < uInc);
}

DWORD Blake2BUpdate
(
	_In_ PBLAKE2B_STATE pState,
	_In_ PBYTE pInput,
	_In_ DWORD cbInput
)
{
	while (cbInput > BLAKE2B_BLOCKBYTES) {
		Blake2BIncrementCounter(pState, BLAKE2B_BLOCKBYTES);
		F(pState, pInput);
		pInput += BLAKE2B_BLOCKBYTES;
		cbInput -= BLAKE2B_BLOCKBYTES;
	}

	memcpy(pState->Buffer + pState->cbBuffer, pInput, cbInput);
	pState->cbBuffer += cbInput;
	return 0;
}

PBLAKE2B_STATE Blake2BInit
(
	_In_ PBYTE pKey,
	_In_ DWORD cbKey
)
{
	BLAKE2B_PARAM Param;
	UINT64 Blake2bIV[8] = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };
	DWORD i = 0;
	PBLAKE2B_STATE Result = NULL;
	PUINT64 pParam = NULL;
	BYTE TempBlock[BLAKE2B_BLOCKBYTES];

	RtlSecureZeroMemory(&Param, sizeof(Param));
	Param.cbDigest = BLAKE2B_OUTBYTES;
	Param.uFanOut = 1;
	Param.uDepth = 1;

	pParam = &Param;
	Result = ALLOC(sizeof(BLAKE2B_STATE));
	for (i = 0; i < _countof(Blake2bIV); i++) {
		Result->h[i] = Blake2bIV[i];
	}

	for (i = 0; i < _countof(Blake2bIV); i++) {
		Result->h[i] ^= pParam[i];
	}

	Result->cbOutput = Param.cbDigest;
	if (cbKey > 0) {
		RtlSecureZeroMemory(TempBlock, sizeof(TempBlock));
		memcpy(TempBlock, pKey, cbKey);
		Blake2BUpdate(Result, TempBlock, sizeof(TempBlock));
	}

	return Result;
}

DWORD Blake2BFinal
(
	_In_ PBLAKE2B_STATE pState,
	_Out_ PBYTE pOutput
)
{
	UINT8 Buffer[BLAKE2B_OUTBYTES] = { 0 };
	size_t i;

	Blake2BIncrementCounter(pState, pState->cbBuffer);
	pState->f[0] = 0xFFFFFFFFFFFFFFFF;
	RtlSecureZeroMemory(pState->Buffer + pState->cbBuffer, 0, BLAKE2B_BLOCKBYTES - pState->cbBuffer);
	F(pState, pState->Buffer);

	for (i = 0; i < 8; ++i) {
		memcpy(Buffer + sizeof(pState->h[i]) * i, &pState->h[i], sizeof(pState->h[i]));
	}

	memcpy(pOutput, Buffer, pState->cbOutput);
	return 0;
}

PBYTE Blake2B
(
	_In_ PBYTE pData,
	_In_ DWORD cbData,
	_In_ PBYTE pKey,
	_In_ DWORD cbKey
)
{
	PBLAKE2B_STATE pState = NULL;
	PBYTE pResult = ALLOC(BLAKE2B_OUTBYTES);

	pState = Blake2BInit(pKey, cbKey);
	Blake2BUpdate(pState, pData, cbData);
	Blake2BFinal(pState, pResult);
	FREE(pState);

	return pResult;
}