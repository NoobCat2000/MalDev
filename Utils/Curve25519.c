#include "pch.h"

VOID Curve25519Prepare
(
	_In_ PBYTE pPrivKey
)
{
	pPrivKey[0] &= 0xf8;
	pPrivKey[31] &= 0x7f;
	pPrivKey[31] |= 0x40;
}

VOID F25519Add
(
	_Out_ PBYTE pOutput,
	_In_ PBYTE a,
	_In_ PBYTE b
)
{
	UINT16 c = 0;
	DWORD i;

	for (i = 0; i < F25519_SIZE; i++) {
		c >>= 8;
		c += ((UINT16)a[i]) + ((UINT16)b[i]);
		pOutput[i] = c;
	}

	pOutput[31] &= 127;
	c = (c >> 7) * 19;
	for (i = 0; i < F25519_SIZE; i++) {
		c += pOutput[i];
		pOutput[i] = c;
		c >>= 8;
	}
}

VOID F25519Sub
(
	_Out_ PBYTE pOutput,
	_In_ PBYTE a,
	_In_ PBYTE b
)
{
	UINT32 c = 0;
	DWORD i;

	c = 218;
	for (i = 0; i + 1 < F25519_SIZE; i++) {
		c += 65280 + ((UINT32)a[i]) - ((UINT32)b[i]);
		pOutput[i] = c;
		c >>= 8;
	}

	c += ((UINT32)a[31]) - ((UINT32)b[31]);
	pOutput[31] = c & 127;
	c = (c >> 7) * 19;
	for (i = 0; i < F25519_SIZE; i++) {
		c += pOutput[i];
		pOutput[i] = c;
		c >>= 8;
	}
}

VOID F25519MulDistinct
(
	_Out_ PBYTE pOutput,
	_In_ PBYTE a,
	_In_ PBYTE b
)
{
	UINT32 c = 0;
	DWORD i;

	for (i = 0; i < F25519_SIZE; i++) {
		DWORD j;

		c >>= 8;
		for (j = 0; j <= i; j++)
			c += ((UINT32)a[j]) * ((UINT32)b[i - j]);

		for (; j < F25519_SIZE; j++)
			c += ((UINT32)a[j]) *
			((UINT32)b[i + F25519_SIZE - j]) * 38;

		pOutput[i] = c;
	}

	pOutput[31] &= 127;
	c = (c >> 7) * 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += pOutput[i];
		pOutput[i] = c;
		c >>= 8;
	}
}

VOID F25519MulC
(
	_Out_ PBYTE r,
	_In_ PBYTE a,
	_In_ UINT32 b
)
{
	UINT32 c = 0;
	DWORD i;

	for (i = 0; i < F25519_SIZE; i++) {
		c >>= 8;
		c += b * ((UINT32)a[i]);
		r[i] = c;
	}

	r[31] &= 127;
	c >>= 7;
	c *= 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += r[i];
		r[i] = c;
		c >>= 8;
	}
}

VOID XcDiffAdd
(
	_In_ PBYTE x5,
	_In_ PBYTE z5,
	_In_ PBYTE x1,
	_In_ PBYTE z1,
	_In_ PBYTE x2,
	_In_ PBYTE z2,
	_In_ PBYTE x3,
	_In_ PBYTE z3
)
{
	BYTE da[F25519_SIZE];
	BYTE cb[F25519_SIZE];
	BYTE a[F25519_SIZE];
	BYTE b[F25519_SIZE];

	F25519Add(a, x2, z2);
	F25519Sub(b, x3, z3);
	F25519MulDistinct(da, a, b);

	F25519Sub(b, x2, z2);
	F25519Add(a, x3, z3);
	F25519MulDistinct(cb, a, b);

	F25519Add(a, da, cb);
	F25519MulDistinct(b, a, a);
	F25519MulDistinct(x5, z1, b);

	F25519Sub(a, da, cb);
	F25519MulDistinct(b, a, a);
	F25519MulDistinct(z5, x1, b);
}

VOID F25519Select
(
	_Out_ PBYTE pDst,
	_In_ PBYTE pZero,
	_In_ PBYTE pOne,
	_In_ BYTE bCondition
)
{
	BYTE mask = -bCondition;
	DWORD i;

	for (i = 0; i < F25519_SIZE; i++) {
		pDst[i] = pZero[i] ^ (mask & (pOne[i] ^ pZero[i]));
	}
}

VOID XcDouble
(
	PBYTE x3,
	PBYTE z3,
	PBYTE x1,
	PBYTE z1
)
{
	BYTE x1sq[F25519_SIZE];
	BYTE z1sq[F25519_SIZE];
	BYTE x1z1[F25519_SIZE];
	BYTE a[F25519_SIZE];

	F25519MulDistinct(x1sq, x1, x1);
	F25519MulDistinct(z1sq, z1, z1);
	F25519MulDistinct(x1z1, x1, z1);

	F25519Sub(a, x1sq, z1sq);
	F25519MulDistinct(x3, a, a);

	F25519MulC(a, x1z1, 486662);
	F25519Add(a, x1sq, a);
	F25519Add(a, z1sq, a);
	F25519MulDistinct(x1sq, x1z1, a);
	F25519MulC(z3, x1sq, 4);
}

VOID F25519Normalize
(
	_Inout_ PBYTE x
)
{
	BYTE minusp[F25519_SIZE];
	UINT16 c;
	DWORD i;

	c = (x[31] >> 7) * 19;
	x[31] &= 127;

	for (i = 0; i < F25519_SIZE; i++) {
		c += x[i];
		x[i] = c;
		c >>= 8;
	}

	c = 19;

	for (i = 0; i + 1 < F25519_SIZE; i++) {
		c += x[i];
		minusp[i] = c;
		c >>= 8;
	}

	c += ((UINT16)x[i]) - 128;
	minusp[31] = c;

	F25519Select(x, minusp, x, (c >> 15) & 1);
}

VOID F25519InvDistinct
(
	_Out_ PBYTE pOutput,
	_In_ PBYTE x
)
{
	BYTE s[F25519_SIZE];
	DWORD i;

	F25519MulDistinct(s, x, x);
	F25519MulDistinct(pOutput, s, x);
	for (i = 0; i < 248; i++) {
		F25519MulDistinct(s, pOutput, pOutput);
		F25519MulDistinct(pOutput, s, x);
	}

	F25519MulDistinct(s, pOutput, pOutput);
	F25519MulDistinct(pOutput, s, s);
	F25519MulDistinct(s, pOutput, x);
	F25519MulDistinct(pOutput, s, s);
	F25519MulDistinct(s, pOutput, pOutput);
	F25519MulDistinct(pOutput, s, x);
	F25519MulDistinct(s, pOutput, pOutput);
	F25519MulDistinct(pOutput, s, x);
}

VOID Curve25519Smult
(
	_Out_ PBYTE* pOutput,
	_In_ PBYTE pQ,
	_In_ PBYTE pE
)
{
	BYTE xm[F25519_SIZE];
	BYTE zm[F25519_SIZE] = { 1 };
	BYTE F25519One[F25519_SIZE] = { 1 };
	BYTE xm1[F25519_SIZE] = { 1 };
	BYTE zm1[F25519_SIZE] = { 0 };
	INT32 i;

	memcpy(xm, pQ, F25519_SIZE);
	for (i = 253; i >= 0; i--) {
		DWORD dwBit = (pE[i >> 3] >> (i & 7)) & 1;
		BYTE xms[F25519_SIZE];
		BYTE zms[F25519_SIZE];

		XcDiffAdd(xm1, zm1, pQ, F25519One, xm, zm, xm1, zm1);
		XcDouble(xm, zm, xm, zm);
		XcDiffAdd(xms, zms, xm1, zm1, xm, zm, pQ, F25519One);
		F25519Select(xm1, xm1, xm, dwBit);
		F25519Select(zm1, zm1, zm, dwBit);
		F25519Select(xm, xm, xms, dwBit);
		F25519Select(zm, zm, zms, dwBit);
	}

	F25519InvDistinct(zm1, zm);
	F25519MulDistinct(pOutput, zm1, xm);
	F25519Normalize(pOutput);
}

VOID ComputeX25519
(
	_Out_ PBYTE pSharedSecret,
	_In_ PBYTE pMyPrivateKey,
	_In_ PBYTE pTheirPublicKey
)
{
	BYTE ClampedPrivateKey[X25519_KEY_SIZE];
	memcpy(ClampedPrivateKey, pMyPrivateKey, X25519_KEY_SIZE);
	Curve25519Prepare(ClampedPrivateKey);
	Curve25519Smult(pSharedSecret, pTheirPublicKey, ClampedPrivateKey);
	RtlSecureZeroMemory(ClampedPrivateKey, X25519_KEY_SIZE);
}

PSTANZA AgeRecipientWrap
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer,
	_In_ PBYTE pTheirPubKey
)
{
	PBYTE pOurPubKey = NULL;
	BYTE BasePoint[] = { 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	PBYTE pEphemeral = NULL;
	PBYTE pSharedSecret = NULL;
	PBYTE pSalt = NULL;
	PBYTE pWrappingKey = NULL;
	PBYTE pWrappedKey = NULL;
	PSTANZA pResult = NULL;
	BYTE Chacha20Nonce[CHACHA20_NONCE_SIZE];
	BYTE Info[] = "age-encryption.org/v1/X25519";
	DWORD cbWrappedKey = 0;

	RtlSecureZeroMemory(Chacha20Nonce, sizeof(Chacha20Nonce));
	pEphemeral = GenRandomBytes(X25519_SCALAR_SIZE);
	if (pEphemeral == NULL) {
		goto CLEANUP;
	}

	pOurPubKey = ALLOC(X25519_SHARED_SIZE);
	pSharedSecret = ALLOC(X25519_SHARED_SIZE);
	ComputeX25519(pOurPubKey, pEphemeral, BasePoint);
	ComputeX25519(pSharedSecret, pEphemeral, pTheirPubKey);
	pSalt = ALLOC(2 * X25519_KEY_SIZE);
	memcpy(pSalt, pOurPubKey, X25519_KEY_SIZE);
	memcpy(pSalt + X25519_KEY_SIZE, pTheirPubKey, X25519_KEY_SIZE);
	pWrappingKey = HKDFGenerate(pSalt, 2 * X25519_KEY_SIZE, pSharedSecret, X25519_SHARED_SIZE, Info, lstrlenA(Info), CHACHA20_KEY_SIZE);
	if (pWrappingKey == NULL) {
		goto CLEANUP;
	}

	Chacha20Poly1305Encrypt(pWrappingKey, Chacha20Nonce, pBuffer, cbBuffer, NULL, 0, &pWrappedKey, &cbWrappedKey);
	if (pWrappedKey == NULL || cbWrappedKey == 0) {
		goto CLEANUP;
	}

	pResult = ALLOC(sizeof(STANZA));
	pResult->lpType = "X25519";
	pResult->pArgs = ALLOC(sizeof(LPSTR));
	pResult->pArgs[0] = Base64Encode(pOurPubKey, X25519_KEY_SIZE, TRUE);
	pResult->dwArgc = 1;
	pResult->pBody = pWrappedKey;
	pResult->cbBody = cbWrappedKey;

CLEANUP:
	if (pEphemeral != NULL) {
		FREE(pEphemeral);
	}

	if (pWrappingKey != NULL) {
		FREE(pWrappingKey);
	}

	if (pSalt != NULL) {
		FREE(pSalt);
	}

	if (pSharedSecret != NULL) {
		FREE(pSharedSecret);
	}

	if (pOurPubKey != NULL) {
		FREE(pOurPubKey);
	}

	return pResult;
}

VOID FreeStanza
(
	_In_ PSTANZA pInput
)
{
	for (DWORD i = 0; i < pInput->dwArgc; i++) {
		FREE(pInput->pArgs[i]);
	}

	FREE(pInput->pArgs);
	FREE(pInput->pBody);
}

VOID FEToBytes
(
	_In_ PBYTE s,
	_In_ PBYTE h
)
{
	INT32 h0 = h[0];
	INT32 h1 = h[1];
	INT32 h2 = h[2];
	INT32 h3 = h[3];
	INT32 h4 = h[4];
	INT32 h5 = h[5];
	INT32 h6 = h[6];
	INT32 h7 = h[7];
	INT32 h8 = h[8];
	INT32 h9 = h[9];
	INT32 q;
	INT32 carry0;
	INT32 carry1;
	INT32 carry2;
	INT32 carry3;
	INT32 carry4;
	INT32 carry5;
	INT32 carry6;
	INT32 carry7;
	INT32 carry8;
	INT32 carry9;
	q = (19 * h9 + (((INT32)1) << 24)) >> 25;
	q = (h0 + q) >> 26;
	q = (h1 + q) >> 25;
	q = (h2 + q) >> 26;
	q = (h3 + q) >> 25;
	q = (h4 + q) >> 26;
	q = (h5 + q) >> 25;
	q = (h6 + q) >> 26;
	q = (h7 + q) >> 25;
	q = (h8 + q) >> 26;
	q = (h9 + q) >> 25;
	/* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
	h0 += 19 * q;
	/* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */
	carry0 = h0 >> 26;
	h1 += carry0;
	h0 -= carry0 << 26;
	carry1 = h1 >> 25;
	h2 += carry1;
	h1 -= carry1 << 25;
	carry2 = h2 >> 26;
	h3 += carry2;
	h2 -= carry2 << 26;
	carry3 = h3 >> 25;
	h4 += carry3;
	h3 -= carry3 << 25;
	carry4 = h4 >> 26;
	h5 += carry4;
	h4 -= carry4 << 26;
	carry5 = h5 >> 25;
	h6 += carry5;
	h5 -= carry5 << 25;
	carry6 = h6 >> 26;
	h7 += carry6;
	h6 -= carry6 << 26;
	carry7 = h7 >> 25;
	h8 += carry7;
	h7 -= carry7 << 25;
	carry8 = h8 >> 26;
	h9 += carry8;
	h8 -= carry8 << 26;
	carry9 = h9 >> 25;
	h9 -= carry9 << 25;

	/* h10 = carry9 */
	/*
	Goal: Output h0+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
	Have h0+...+2^230 h9 between 0 and 2^255-1;
	evidently 2^255 h10-2^255 q = 0.
	Goal: Output h0+...+2^230 h9.
	*/
	s[0] = (BYTE)(h0 >> 0);
	s[1] = (BYTE)(h0 >> 8);
	s[2] = (BYTE)(h0 >> 16);
	s[3] = (BYTE)((h0 >> 24) | (h1 << 2));
	s[4] = (BYTE)(h1 >> 6);
	s[5] = (BYTE)(h1 >> 14);
	s[6] = (BYTE)((h1 >> 22) | (h2 << 3));
	s[7] = (BYTE)(h2 >> 5);
	s[8] = (BYTE)(h2 >> 13);
	s[9] = (BYTE)((h2 >> 21) | (h3 << 5));
	s[10] = (BYTE)(h3 >> 3);
	s[11] = (BYTE)(h3 >> 11);
	s[12] = (BYTE)((h3 >> 19) | (h4 << 6));
	s[13] = (BYTE)(h4 >> 2);
	s[14] = (BYTE)(h4 >> 10);
	s[15] = (BYTE)(h4 >> 18);
	s[16] = (BYTE)(h5 >> 0);
	s[17] = (BYTE)(h5 >> 8);
	s[18] = (BYTE)(h5 >> 16);
	s[19] = (BYTE)((h5 >> 24) | (h6 << 1));
	s[20] = (BYTE)(h6 >> 7);
	s[21] = (BYTE)(h6 >> 15);
	s[22] = (BYTE)((h6 >> 23) | (h7 << 3));
	s[23] = (BYTE)(h7 >> 5);
	s[24] = (BYTE)(h7 >> 13);
	s[25] = (BYTE)((h7 >> 21) | (h8 << 4));
	s[26] = (BYTE)(h8 >> 4);
	s[27] = (BYTE)(h8 >> 12);
	s[28] = (BYTE)((h8 >> 20) | (h9 << 6));
	s[29] = (BYTE)(h9 >> 2);
	s[30] = (BYTE)(h9 >> 10);
	s[31] = (BYTE)(h9 >> 18);
}

VOID FE0
(
	_In_ PBYTE lpBuffer
)
{
	lpBuffer[0] = 0;
	lpBuffer[1] = 0;
	lpBuffer[2] = 0;
	lpBuffer[3] = 0;
	lpBuffer[4] = 0;
	lpBuffer[5] = 0;
	lpBuffer[6] = 0;
	lpBuffer[7] = 0;
	lpBuffer[8] = 0;
	lpBuffer[9] = 0;
}

VOID FE1
(
	_In_ PBYTE lpBuffer
)
{
	lpBuffer[0] = 1;
	lpBuffer[1] = 0;
	lpBuffer[2] = 0;
	lpBuffer[3] = 0;
	lpBuffer[4] = 0;
	lpBuffer[5] = 0;
	lpBuffer[6] = 0;
	lpBuffer[7] = 0;
	lpBuffer[8] = 0;
	lpBuffer[9] = 0;
}

VOID FEMul
(
	_In_ PBYTE h,
	_In_ PBYTE f,
	_In_ PBYTE g
)
{
	INT32 f0 = f[0];
	INT32 f1 = f[1];
	INT32 f2 = f[2];
	INT32 f3 = f[3];
	INT32 f4 = f[4];
	INT32 f5 = f[5];
	INT32 f6 = f[6];
	INT32 f7 = f[7];
	INT32 f8 = f[8];
	INT32 f9 = f[9];
	INT32 g0 = g[0];
	INT32 g1 = g[1];
	INT32 g2 = g[2];
	INT32 g3 = g[3];
	INT32 g4 = g[4];
	INT32 g5 = g[5];
	INT32 g6 = g[6];
	INT32 g7 = g[7];
	INT32 g8 = g[8];
	INT32 g9 = g[9];
	INT32 g1_19 = 19 * g1; /* 1.959375*2^29 */
	INT32 g2_19 = 19 * g2; /* 1.959375*2^30; still ok */
	INT32 g3_19 = 19 * g3;
	INT32 g4_19 = 19 * g4;
	INT32 g5_19 = 19 * g5;
	INT32 g6_19 = 19 * g6;
	INT32 g7_19 = 19 * g7;
	INT32 g8_19 = 19 * g8;
	INT32 g9_19 = 19 * g9;
	INT32 f1_2 = 2 * f1;
	INT32 f3_2 = 2 * f3;
	INT32 f5_2 = 2 * f5;
	INT32 f7_2 = 2 * f7;
	INT32 f9_2 = 2 * f9;
	INT64 f0g0 = f0 * (INT64)g0;
	INT64 f0g1 = f0 * (INT64)g1;
	INT64 f0g2 = f0 * (INT64)g2;
	INT64 f0g3 = f0 * (INT64)g3;
	INT64 f0g4 = f0 * (INT64)g4;
	INT64 f0g5 = f0 * (INT64)g5;
	INT64 f0g6 = f0 * (INT64)g6;
	INT64 f0g7 = f0 * (INT64)g7;
	INT64 f0g8 = f0 * (INT64)g8;
	INT64 f0g9 = f0 * (INT64)g9;
	INT64 f1g0 = f1 * (INT64)g0;
	INT64 f1g1_2 = f1_2 * (INT64)g1;
	INT64 f1g2 = f1 * (INT64)g2;
	INT64 f1g3_2 = f1_2 * (INT64)g3;
	INT64 f1g4 = f1 * (INT64)g4;
	INT64 f1g5_2 = f1_2 * (INT64)g5;
	INT64 f1g6 = f1 * (INT64)g6;
	INT64 f1g7_2 = f1_2 * (INT64)g7;
	INT64 f1g8 = f1 * (INT64)g8;
	INT64 f1g9_38 = f1_2 * (INT64)g9_19;
	INT64 f2g0 = f2 * (INT64)g0;
	INT64 f2g1 = f2 * (INT64)g1;
	INT64 f2g2 = f2 * (INT64)g2;
	INT64 f2g3 = f2 * (INT64)g3;
	INT64 f2g4 = f2 * (INT64)g4;
	INT64 f2g5 = f2 * (INT64)g5;
	INT64 f2g6 = f2 * (INT64)g6;
	INT64 f2g7 = f2 * (INT64)g7;
	INT64 f2g8_19 = f2 * (INT64)g8_19;
	INT64 f2g9_19 = f2 * (INT64)g9_19;
	INT64 f3g0 = f3 * (INT64)g0;
	INT64 f3g1_2 = f3_2 * (INT64)g1;
	INT64 f3g2 = f3 * (INT64)g2;
	INT64 f3g3_2 = f3_2 * (INT64)g3;
	INT64 f3g4 = f3 * (INT64)g4;
	INT64 f3g5_2 = f3_2 * (INT64)g5;
	INT64 f3g6 = f3 * (INT64)g6;
	INT64 f3g7_38 = f3_2 * (INT64)g7_19;
	INT64 f3g8_19 = f3 * (INT64)g8_19;
	INT64 f3g9_38 = f3_2 * (INT64)g9_19;
	INT64 f4g0 = f4 * (INT64)g0;
	INT64 f4g1 = f4 * (INT64)g1;
	INT64 f4g2 = f4 * (INT64)g2;
	INT64 f4g3 = f4 * (INT64)g3;
	INT64 f4g4 = f4 * (INT64)g4;
	INT64 f4g5 = f4 * (INT64)g5;
	INT64 f4g6_19 = f4 * (INT64)g6_19;
	INT64 f4g7_19 = f4 * (INT64)g7_19;
	INT64 f4g8_19 = f4 * (INT64)g8_19;
	INT64 f4g9_19 = f4 * (INT64)g9_19;
	INT64 f5g0 = f5 * (INT64)g0;
	INT64 f5g1_2 = f5_2 * (INT64)g1;
	INT64 f5g2 = f5 * (INT64)g2;
	INT64 f5g3_2 = f5_2 * (INT64)g3;
	INT64 f5g4 = f5 * (INT64)g4;
	INT64 f5g5_38 = f5_2 * (INT64)g5_19;
	INT64 f5g6_19 = f5 * (INT64)g6_19;
	INT64 f5g7_38 = f5_2 * (INT64)g7_19;
	INT64 f5g8_19 = f5 * (INT64)g8_19;
	INT64 f5g9_38 = f5_2 * (INT64)g9_19;
	INT64 f6g0 = f6 * (INT64)g0;
	INT64 f6g1 = f6 * (INT64)g1;
	INT64 f6g2 = f6 * (INT64)g2;
	INT64 f6g3 = f6 * (INT64)g3;
	INT64 f6g4_19 = f6 * (INT64)g4_19;
	INT64 f6g5_19 = f6 * (INT64)g5_19;
	INT64 f6g6_19 = f6 * (INT64)g6_19;
	INT64 f6g7_19 = f6 * (INT64)g7_19;
	INT64 f6g8_19 = f6 * (INT64)g8_19;
	INT64 f6g9_19 = f6 * (INT64)g9_19;
	INT64 f7g0 = f7 * (INT64)g0;
	INT64 f7g1_2 = f7_2 * (INT64)g1;
	INT64 f7g2 = f7 * (INT64)g2;
	INT64 f7g3_38 = f7_2 * (INT64)g3_19;
	INT64 f7g4_19 = f7 * (INT64)g4_19;
	INT64 f7g5_38 = f7_2 * (INT64)g5_19;
	INT64 f7g6_19 = f7 * (INT64)g6_19;
	INT64 f7g7_38 = f7_2 * (INT64)g7_19;
	INT64 f7g8_19 = f7 * (INT64)g8_19;
	INT64 f7g9_38 = f7_2 * (INT64)g9_19;
	INT64 f8g0 = f8 * (INT64)g0;
	INT64 f8g1 = f8 * (INT64)g1;
	INT64 f8g2_19 = f8 * (INT64)g2_19;
	INT64 f8g3_19 = f8 * (INT64)g3_19;
	INT64 f8g4_19 = f8 * (INT64)g4_19;
	INT64 f8g5_19 = f8 * (INT64)g5_19;
	INT64 f8g6_19 = f8 * (INT64)g6_19;
	INT64 f8g7_19 = f8 * (INT64)g7_19;
	INT64 f8g8_19 = f8 * (INT64)g8_19;
	INT64 f8g9_19 = f8 * (INT64)g9_19;
	INT64 f9g0 = f9 * (INT64)g0;
	INT64 f9g1_38 = f9_2 * (INT64)g1_19;
	INT64 f9g2_19 = f9 * (INT64)g2_19;
	INT64 f9g3_38 = f9_2 * (INT64)g3_19;
	INT64 f9g4_19 = f9 * (INT64)g4_19;
	INT64 f9g5_38 = f9_2 * (INT64)g5_19;
	INT64 f9g6_19 = f9 * (INT64)g6_19;
	INT64 f9g7_38 = f9_2 * (INT64)g7_19;
	INT64 f9g8_19 = f9 * (INT64)g8_19;
	INT64 f9g9_38 = f9_2 * (INT64)g9_19;
	INT64 h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
	INT64 h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
	INT64 h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
	INT64 h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
	INT64 h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
	INT64 h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
	INT64 h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38;
	INT64 h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19;
	INT64 h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38;
	INT64 h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;
	INT64 carry0;
	INT64 carry1;
	INT64 carry2;
	INT64 carry3;
	INT64 carry4;
	INT64 carry5;
	INT64 carry6;
	INT64 carry7;
	INT64 carry8;
	INT64 carry9;

	carry0 = (h0 + (INT64)(1 << 25)) >> 26;
	h1 += carry0;
	h0 -= carry0 << 26;
	carry4 = (h4 + (INT64)(1 << 25)) >> 26;
	h5 += carry4;
	h4 -= carry4 << 26;

	carry1 = (h1 + (INT64)(1 << 24)) >> 25;
	h2 += carry1;
	h1 -= carry1 << 25;
	carry5 = (h5 + (INT64)(1 << 24)) >> 25;
	h6 += carry5;
	h5 -= carry5 << 25;

	carry2 = (h2 + (INT64)(1 << 25)) >> 26;
	h3 += carry2;
	h2 -= carry2 << 26;
	carry6 = (h6 + (INT64)(1 << 25)) >> 26;
	h7 += carry6;
	h6 -= carry6 << 26;

	carry3 = (h3 + (INT64)(1 << 24)) >> 25;
	h4 += carry3;
	h3 -= carry3 << 25;
	carry7 = (h7 + (INT64)(1 << 24)) >> 25;
	h8 += carry7;
	h7 -= carry7 << 25;

	carry4 = (h4 + (INT64)(1 << 25)) >> 26;
	h5 += carry4;
	h4 -= carry4 << 26;
	carry8 = (h8 + (INT64)(1 << 25)) >> 26;
	h9 += carry8;
	h8 -= carry8 << 26;

	carry9 = (h9 + (INT64)(1 << 24)) >> 25;
	h0 += carry9 * 19;
	h9 -= carry9 << 25;

	carry0 = (h0 + (INT64)(1 << 25)) >> 26;
	h1 += carry0;
	h0 -= carry0 << 26;

	h[0] = (INT32)h0;
	h[1] = (INT32)h1;
	h[2] = (INT32)h2;
	h[3] = (INT32)h3;
	h[4] = (INT32)h4;
	h[5] = (INT32)h5;
	h[6] = (INT32)h6;
	h[7] = (INT32)h7;
	h[8] = (INT32)h8;
	h[9] = (INT32)h9;
}

VOID FESub
(
	_In_ PBYTE h,
	_In_ PBYTE f,
	_In_ PBYTE g
)
{
	INT32 f0 = f[0];
	INT32 f1 = f[1];
	INT32 f2 = f[2];
	INT32 f3 = f[3];
	INT32 f4 = f[4];
	INT32 f5 = f[5];
	INT32 f6 = f[6];
	INT32 f7 = f[7];
	INT32 f8 = f[8];
	INT32 f9 = f[9];
	INT32 g0 = g[0];
	INT32 g1 = g[1];
	INT32 g2 = g[2];
	INT32 g3 = g[3];
	INT32 g4 = g[4];
	INT32 g5 = g[5];
	INT32 g6 = g[6];
	INT32 g7 = g[7];
	INT32 g8 = g[8];
	INT32 g9 = g[9];
	INT32 h0 = f0 - g0;
	INT32 h1 = f1 - g1;
	INT32 h2 = f2 - g2;
	INT32 h3 = f3 - g3;
	INT32 h4 = f4 - g4;
	INT32 h5 = f5 - g5;
	INT32 h6 = f6 - g6;
	INT32 h7 = f7 - g7;
	INT32 h8 = f8 - g8;
	INT32 h9 = f9 - g9;

	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
	h[5] = h5;
	h[6] = h6;
	h[7] = h7;
	h[8] = h8;
	h[9] = h9;
}

VOID FEAdd
(
	_In_ PBYTE h,
	_In_ PBYTE f,
	_In_ PBYTE g
)
{
	INT32 f0 = f[0];
	INT32 f1 = f[1];
	INT32 f2 = f[2];
	INT32 f3 = f[3];
	INT32 f4 = f[4];
	INT32 f5 = f[5];
	INT32 f6 = f[6];
	INT32 f7 = f[7];
	INT32 f8 = f[8];
	INT32 f9 = f[9];
	INT32 g0 = g[0];
	INT32 g1 = g[1];
	INT32 g2 = g[2];
	INT32 g3 = g[3];
	INT32 g4 = g[4];
	INT32 g5 = g[5];
	INT32 g6 = g[6];
	INT32 g7 = g[7];
	INT32 g8 = g[8];
	INT32 g9 = g[9];
	INT32 h0 = f0 + g0;
	INT32 h1 = f1 + g1;
	INT32 h2 = f2 + g2;
	INT32 h3 = f3 + g3;
	INT32 h4 = f4 + g4;
	INT32 h5 = f5 + g5;
	INT32 h6 = f6 + g6;
	INT32 h7 = f7 + g7;
	INT32 h8 = f8 + g8;
	INT32 h9 = f9 + g9;

	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
	h[5] = h5;
	h[6] = h6;
	h[7] = h7;
	h[8] = h8;
	h[9] = h9;
}

VOID FESq
(
	_In_ PBYTE h,
	_In_ PBYTE f
)
{
	INT32 f0 = f[0];
	INT32 f1 = f[1];
	INT32 f2 = f[2];
	INT32 f3 = f[3];
	INT32 f4 = f[4];
	INT32 f5 = f[5];
	INT32 f6 = f[6];
	INT32 f7 = f[7];
	INT32 f8 = f[8];
	INT32 f9 = f[9];
	INT32 f0_2 = 2 * f0;
	INT32 f1_2 = 2 * f1;
	INT32 f2_2 = 2 * f2;
	INT32 f3_2 = 2 * f3;
	INT32 f4_2 = 2 * f4;
	INT32 f5_2 = 2 * f5;
	INT32 f6_2 = 2 * f6;
	INT32 f7_2 = 2 * f7;
	INT32 f5_38 = 38 * f5; /* 1.959375*2^30 */
	INT32 f6_19 = 19 * f6; /* 1.959375*2^30 */
	INT32 f7_38 = 38 * f7; /* 1.959375*2^30 */
	INT32 f8_19 = 19 * f8; /* 1.959375*2^30 */
	INT32 f9_38 = 38 * f9; /* 1.959375*2^30 */
	INT64 f0f0 = f0 * (INT64)f0;
	INT64 f0f1_2 = f0_2 * (INT64)f1;
	INT64 f0f2_2 = f0_2 * (INT64)f2;
	INT64 f0f3_2 = f0_2 * (INT64)f3;
	INT64 f0f4_2 = f0_2 * (INT64)f4;
	INT64 f0f5_2 = f0_2 * (INT64)f5;
	INT64 f0f6_2 = f0_2 * (INT64)f6;
	INT64 f0f7_2 = f0_2 * (INT64)f7;
	INT64 f0f8_2 = f0_2 * (INT64)f8;
	INT64 f0f9_2 = f0_2 * (INT64)f9;
	INT64 f1f1_2 = f1_2 * (INT64)f1;
	INT64 f1f2_2 = f1_2 * (INT64)f2;
	INT64 f1f3_4 = f1_2 * (INT64)f3_2;
	INT64 f1f4_2 = f1_2 * (INT64)f4;
	INT64 f1f5_4 = f1_2 * (INT64)f5_2;
	INT64 f1f6_2 = f1_2 * (INT64)f6;
	INT64 f1f7_4 = f1_2 * (INT64)f7_2;
	INT64 f1f8_2 = f1_2 * (INT64)f8;
	INT64 f1f9_76 = f1_2 * (INT64)f9_38;
	INT64 f2f2 = f2 * (INT64)f2;
	INT64 f2f3_2 = f2_2 * (INT64)f3;
	INT64 f2f4_2 = f2_2 * (INT64)f4;
	INT64 f2f5_2 = f2_2 * (INT64)f5;
	INT64 f2f6_2 = f2_2 * (INT64)f6;
	INT64 f2f7_2 = f2_2 * (INT64)f7;
	INT64 f2f8_38 = f2_2 * (INT64)f8_19;
	INT64 f2f9_38 = f2 * (INT64)f9_38;
	INT64 f3f3_2 = f3_2 * (INT64)f3;
	INT64 f3f4_2 = f3_2 * (INT64)f4;
	INT64 f3f5_4 = f3_2 * (INT64)f5_2;
	INT64 f3f6_2 = f3_2 * (INT64)f6;
	INT64 f3f7_76 = f3_2 * (INT64)f7_38;
	INT64 f3f8_38 = f3_2 * (INT64)f8_19;
	INT64 f3f9_76 = f3_2 * (INT64)f9_38;
	INT64 f4f4 = f4 * (INT64)f4;
	INT64 f4f5_2 = f4_2 * (INT64)f5;
	INT64 f4f6_38 = f4_2 * (INT64)f6_19;
	INT64 f4f7_38 = f4 * (INT64)f7_38;
	INT64 f4f8_38 = f4_2 * (INT64)f8_19;
	INT64 f4f9_38 = f4 * (INT64)f9_38;
	INT64 f5f5_38 = f5 * (INT64)f5_38;
	INT64 f5f6_38 = f5_2 * (INT64)f6_19;
	INT64 f5f7_76 = f5_2 * (INT64)f7_38;
	INT64 f5f8_38 = f5_2 * (INT64)f8_19;
	INT64 f5f9_76 = f5_2 * (INT64)f9_38;
	INT64 f6f6_19 = f6 * (INT64)f6_19;
	INT64 f6f7_38 = f6 * (INT64)f7_38;
	INT64 f6f8_38 = f6_2 * (INT64)f8_19;
	INT64 f6f9_38 = f6 * (INT64)f9_38;
	INT64 f7f7_38 = f7 * (INT64)f7_38;
	INT64 f7f8_38 = f7_2 * (INT64)f8_19;
	INT64 f7f9_76 = f7_2 * (INT64)f9_38;
	INT64 f8f8_19 = f8 * (INT64)f8_19;
	INT64 f8f9_38 = f8 * (INT64)f9_38;
	INT64 f9f9_38 = f9 * (INT64)f9_38;
	INT64 h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
	INT64 h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
	INT64 h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
	INT64 h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
	INT64 h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
	INT64 h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
	INT64 h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
	INT64 h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
	INT64 h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
	INT64 h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
	INT64 carry0;
	INT64 carry1;
	INT64 carry2;
	INT64 carry3;
	INT64 carry4;
	INT64 carry5;
	INT64 carry6;
	INT64 carry7;
	INT64 carry8;
	INT64 carry9;
	carry0 = (h0 + (INT64)(1 << 25)) >> 26;
	h1 += carry0;
	h0 -= carry0 << 26;
	carry4 = (h4 + (INT64)(1 << 25)) >> 26;
	h5 += carry4;
	h4 -= carry4 << 26;
	carry1 = (h1 + (INT64)(1 << 24)) >> 25;
	h2 += carry1;
	h1 -= carry1 << 25;
	carry5 = (h5 + (INT64)(1 << 24)) >> 25;
	h6 += carry5;
	h5 -= carry5 << 25;
	carry2 = (h2 + (INT64)(1 << 25)) >> 26;
	h3 += carry2;
	h2 -= carry2 << 26;
	carry6 = (h6 + (INT64)(1 << 25)) >> 26;
	h7 += carry6;
	h6 -= carry6 << 26;
	carry3 = (h3 + (INT64)(1 << 24)) >> 25;
	h4 += carry3;
	h3 -= carry3 << 25;
	carry7 = (h7 + (INT64)(1 << 24)) >> 25;
	h8 += carry7;
	h7 -= carry7 << 25;
	carry4 = (h4 + (INT64)(1 << 25)) >> 26;
	h5 += carry4;
	h4 -= carry4 << 26;
	carry8 = (h8 + (INT64)(1 << 25)) >> 26;
	h9 += carry8;
	h8 -= carry8 << 26;
	carry9 = (h9 + (INT64)(1 << 24)) >> 25;
	h0 += carry9 * 19;
	h9 -= carry9 << 25;
	carry0 = (h0 + (INT64)(1 << 25)) >> 26;
	h1 += carry0;
	h0 -= carry0 << 26;
	h[0] = (INT32)h0;
	h[1] = (INT32)h1;
	h[2] = (INT32)h2;
	h[3] = (INT32)h3;
	h[4] = (INT32)h4;
	h[5] = (INT32)h5;
	h[6] = (INT32)h6;
	h[7] = (INT32)h7;
	h[8] = (INT32)h8;
	h[9] = (INT32)h9;
}

VOID FESq2
(
	_In_ PBYTE h,
	_In_ PBYTE f
)
{
	INT32 f0 = f[0];
	INT32 f1 = f[1];
	INT32 f2 = f[2];
	INT32 f3 = f[3];
	INT32 f4 = f[4];
	INT32 f5 = f[5];
	INT32 f6 = f[6];
	INT32 f7 = f[7];
	INT32 f8 = f[8];
	INT32 f9 = f[9];
	INT32 f0_2 = 2 * f0;
	INT32 f1_2 = 2 * f1;
	INT32 f2_2 = 2 * f2;
	INT32 f3_2 = 2 * f3;
	INT32 f4_2 = 2 * f4;
	INT32 f5_2 = 2 * f5;
	INT32 f6_2 = 2 * f6;
	INT32 f7_2 = 2 * f7;
	INT32 f5_38 = 38 * f5; /* 1.959375*2^30 */
	INT32 f6_19 = 19 * f6; /* 1.959375*2^30 */
	INT32 f7_38 = 38 * f7; /* 1.959375*2^30 */
	INT32 f8_19 = 19 * f8; /* 1.959375*2^30 */
	INT32 f9_38 = 38 * f9; /* 1.959375*2^30 */
	INT64 f0f0 = f0 * (INT64)f0;
	INT64 f0f1_2 = f0_2 * (INT64)f1;
	INT64 f0f2_2 = f0_2 * (INT64)f2;
	INT64 f0f3_2 = f0_2 * (INT64)f3;
	INT64 f0f4_2 = f0_2 * (INT64)f4;
	INT64 f0f5_2 = f0_2 * (INT64)f5;
	INT64 f0f6_2 = f0_2 * (INT64)f6;
	INT64 f0f7_2 = f0_2 * (INT64)f7;
	INT64 f0f8_2 = f0_2 * (INT64)f8;
	INT64 f0f9_2 = f0_2 * (INT64)f9;
	INT64 f1f1_2 = f1_2 * (INT64)f1;
	INT64 f1f2_2 = f1_2 * (INT64)f2;
	INT64 f1f3_4 = f1_2 * (INT64)f3_2;
	INT64 f1f4_2 = f1_2 * (INT64)f4;
	INT64 f1f5_4 = f1_2 * (INT64)f5_2;
	INT64 f1f6_2 = f1_2 * (INT64)f6;
	INT64 f1f7_4 = f1_2 * (INT64)f7_2;
	INT64 f1f8_2 = f1_2 * (INT64)f8;
	INT64 f1f9_76 = f1_2 * (INT64)f9_38;
	INT64 f2f2 = f2 * (INT64)f2;
	INT64 f2f3_2 = f2_2 * (INT64)f3;
	INT64 f2f4_2 = f2_2 * (INT64)f4;
	INT64 f2f5_2 = f2_2 * (INT64)f5;
	INT64 f2f6_2 = f2_2 * (INT64)f6;
	INT64 f2f7_2 = f2_2 * (INT64)f7;
	INT64 f2f8_38 = f2_2 * (INT64)f8_19;
	INT64 f2f9_38 = f2 * (INT64)f9_38;
	INT64 f3f3_2 = f3_2 * (INT64)f3;
	INT64 f3f4_2 = f3_2 * (INT64)f4;
	INT64 f3f5_4 = f3_2 * (INT64)f5_2;
	INT64 f3f6_2 = f3_2 * (INT64)f6;
	INT64 f3f7_76 = f3_2 * (INT64)f7_38;
	INT64 f3f8_38 = f3_2 * (INT64)f8_19;
	INT64 f3f9_76 = f3_2 * (INT64)f9_38;
	INT64 f4f4 = f4 * (INT64)f4;
	INT64 f4f5_2 = f4_2 * (INT64)f5;
	INT64 f4f6_38 = f4_2 * (INT64)f6_19;
	INT64 f4f7_38 = f4 * (INT64)f7_38;
	INT64 f4f8_38 = f4_2 * (INT64)f8_19;
	INT64 f4f9_38 = f4 * (INT64)f9_38;
	INT64 f5f5_38 = f5 * (INT64)f5_38;
	INT64 f5f6_38 = f5_2 * (INT64)f6_19;
	INT64 f5f7_76 = f5_2 * (INT64)f7_38;
	INT64 f5f8_38 = f5_2 * (INT64)f8_19;
	INT64 f5f9_76 = f5_2 * (INT64)f9_38;
	INT64 f6f6_19 = f6 * (INT64)f6_19;
	INT64 f6f7_38 = f6 * (INT64)f7_38;
	INT64 f6f8_38 = f6_2 * (INT64)f8_19;
	INT64 f6f9_38 = f6 * (INT64)f9_38;
	INT64 f7f7_38 = f7 * (INT64)f7_38;
	INT64 f7f8_38 = f7_2 * (INT64)f8_19;
	INT64 f7f9_76 = f7_2 * (INT64)f9_38;
	INT64 f8f8_19 = f8 * (INT64)f8_19;
	INT64 f8f9_38 = f8 * (INT64)f9_38;
	INT64 f9f9_38 = f9 * (INT64)f9_38;
	INT64 h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
	INT64 h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
	INT64 h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
	INT64 h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
	INT64 h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
	INT64 h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
	INT64 h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
	INT64 h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
	INT64 h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
	INT64 h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
	INT64 carry0;
	INT64 carry1;
	INT64 carry2;
	INT64 carry3;
	INT64 carry4;
	INT64 carry5;
	INT64 carry6;
	INT64 carry7;
	INT64 carry8;
	INT64 carry9;
	h0 += h0;
	h1 += h1;
	h2 += h2;
	h3 += h3;
	h4 += h4;
	h5 += h5;
	h6 += h6;
	h7 += h7;
	h8 += h8;
	h9 += h9;
	carry0 = (h0 + (INT64)(1 << 25)) >> 26;
	h1 += carry0;
	h0 -= carry0 << 26;
	carry4 = (h4 + (INT64)(1 << 25)) >> 26;
	h5 += carry4;
	h4 -= carry4 << 26;
	carry1 = (h1 + (INT64)(1 << 24)) >> 25;
	h2 += carry1;
	h1 -= carry1 << 25;
	carry5 = (h5 + (INT64)(1 << 24)) >> 25;
	h6 += carry5;
	h5 -= carry5 << 25;
	carry2 = (h2 + (INT64)(1 << 25)) >> 26;
	h3 += carry2;
	h2 -= carry2 << 26;
	carry6 = (h6 + (INT64)(1 << 25)) >> 26;
	h7 += carry6;
	h6 -= carry6 << 26;
	carry3 = (h3 + (INT64)(1 << 24)) >> 25;
	h4 += carry3;
	h3 -= carry3 << 25;
	carry7 = (h7 + (INT64)(1 << 24)) >> 25;
	h8 += carry7;
	h7 -= carry7 << 25;
	carry4 = (h4 + (INT64)(1 << 25)) >> 26;
	h5 += carry4;
	h4 -= carry4 << 26;
	carry8 = (h8 + (INT64)(1 << 25)) >> 26;
	h9 += carry8;
	h8 -= carry8 << 26;
	carry9 = (h9 + (INT64)(1 << 24)) >> 25;
	h0 += carry9 * 19;
	h9 -= carry9 << 25;
	carry0 = (h0 + (INT64)(1 << 25)) >> 26;
	h1 += carry0;
	h0 -= carry0 << 26;
	h[0] = (INT32)h0;
	h[1] = (INT32)h1;
	h[2] = (INT32)h2;
	h[3] = (INT32)h3;
	h[4] = (INT32)h4;
	h[5] = (INT32)h5;
	h[6] = (INT32)h6;
	h[7] = (INT32)h7;
	h[8] = (INT32)h8;
	h[9] = (INT32)h9;
}

VOID FEPow22523
(
	_Out_ PBYTE pOutput,
	_In_ PBYTE z
)
{
	INT32 t0[10];
	INT32 t1[10];
	INT32 t2[10];
	INT32 i = 0;
	
	FESq(t0, z);
	for (i = 1; i < 1; ++i) {
		FESq(t0, t0);
	}

	FESq(t1, t0);

	for (i = 1; i < 2; ++i) {
		FESq(t1, t1);
	}

	FEMul(t1, z, t1);
	FEMul(t0, t0, t1);
	FESq(t0, t0);

	for (i = 1; i < 1; ++i) {
		FESq(t0, t0);
	}

	FEMul(t0, t1, t0);
	FESq(t1, t0);

	for (i = 1; i < 5; ++i) {
		FESq(t1, t1);
	}

	FEMul(t0, t1, t0);
	FESq(t1, t0);

	for (i = 1; i < 10; ++i) {
		FESq(t1, t1);
	}

	FEMul(t1, t1, t0);
	FESq(t2, t1);

	for (i = 1; i < 20; ++i) {
		FESq(t2, t2);
	}

	FEMul(t1, t2, t1);
	FESq(t1, t1);

	for (i = 1; i < 10; ++i) {
		FESq(t1, t1);
	}

	FEMul(t0, t1, t0);
	FESq(t1, t0);

	for (i = 1; i < 50; ++i) {
		FESq(t1, t1);
	}

	FEMul(t1, t1, t0);
	FESq(t2, t1);

	for (i = 1; i < 100; ++i) {
		FESq(t2, t2);
	}

	FEMul(t1, t2, t1);
	FESq(t1, t1);

	for (i = 1; i < 50; ++i) {
		FESq(t1, t1);
	}

	FEMul(t0, t1, t0);
	FESq(t0, t0);

	for (i = 1; i < 2; ++i) {
		FESq(t0, t0);
	}

	FEMul(pOutput, t0, z);
	return;
}

INT32 FEIsNonZero
(
	_In_ PBYTE f
)
{
	CHAR s[32];
	CHAR r;

	FEToBytes(s, f);

	r = s[0];
#define F_OR(i) r |= s[i]
	F_OR(1);
	F_OR(2);
	F_OR(3);
	F_OR(4);
	F_OR(5);
	F_OR(6);
	F_OR(7);
	F_OR(8);
	F_OR(9);
	F_OR(10);
	F_OR(11);
	F_OR(12);
	F_OR(13);
	F_OR(14);
	F_OR(15);
	F_OR(16);
	F_OR(17);
	F_OR(18);
	F_OR(19);
	F_OR(20);
	F_OR(21);
	F_OR(22);
	F_OR(23);
	F_OR(24);
	F_OR(25);
	F_OR(26);
	F_OR(27);
	F_OR(28);
	F_OR(29);
	F_OR(30);
	F_OR(31);
#undef F_OR

	return r != 0;
}

VOID FEFromBytes
(
	_In_ PUINT32 h,
	_In_ PBYTE lpBuffer
)
{
	INT64 h0 = *((PUINT32)lpBuffer);
	INT64 h1 = ((*((PUINT32)(lpBuffer + 4))) & 0xFFFFFF) << 6;
	INT64 h2 = ((*((PUINT32)(lpBuffer + 7))) & 0xFFFFFF) << 5;
	INT64 h3 = ((*((PUINT32)(lpBuffer + 10))) & 0xFFFFFF) << 3;
	INT64 h4 = ((*((PUINT32)(lpBuffer + 13))) & 0xFFFFFF) << 2;
	INT64 h5 = (*((PUINT32)(lpBuffer + 16)));
	INT64 h6 = ((*((PUINT32)(lpBuffer + 20))) & 0xFFFFFF) << 7;
	INT64 h7 = ((*((PUINT32)(lpBuffer + 23))) & 0xFFFFFF) << 5;
	INT64 h8 = ((*((PUINT32)(lpBuffer + 26))) & 0xFFFFFF) << 4;
	INT64 h9 = (((*((PUINT32)(lpBuffer + 29))) & 0xFFFFFF) & 8388607) << 2;
	INT64 carry0;
	INT64 carry1;
	INT64 carry2;
	INT64 carry3;
	INT64 carry4;
	INT64 carry5;
	INT64 carry6;
	INT64 carry7;
	INT64 carry8;
	INT64 carry9;

	carry9 = (h9 + (INT64)(1 << 24)) >> 25;
	h0 += carry9 * 19;
	h9 -= carry9 << 25;
	carry1 = (h1 + (INT64)(1 << 24)) >> 25;
	h2 += carry1;
	h1 -= carry1 << 25;
	carry3 = (h3 + (INT64)(1 << 24)) >> 25;
	h4 += carry3;
	h3 -= carry3 << 25;
	carry5 = (h5 + (INT64)(1 << 24)) >> 25;
	h6 += carry5;
	h5 -= carry5 << 25;
	carry7 = (h7 + (INT64)(1 << 24)) >> 25;
	h8 += carry7;
	h7 -= carry7 << 25;
	carry0 = (h0 + (INT64)(1 << 25)) >> 26;
	h1 += carry0;
	h0 -= carry0 << 26;
	carry2 = (h2 + (INT64)(1 << 25)) >> 26;
	h3 += carry2;
	h2 -= carry2 << 26;
	carry4 = (h4 + (INT64)(1 << 25)) >> 26;
	h5 += carry4;
	h4 -= carry4 << 26;
	carry6 = (h6 + (INT64)(1 << 25)) >> 26;
	h7 += carry6;
	h6 -= carry6 << 26;
	carry8 = (h8 + (INT64)(1 << 25)) >> 26;
	h9 += carry8;
	h8 -= carry8 << 26;

	h[0] = (INT32)h0;
	h[1] = (INT32)h1;
	h[2] = (INT32)h2;
	h[3] = (INT32)h3;
	h[4] = (INT32)h4;
	h[5] = (INT32)h5;
	h[6] = (INT32)h6;
	h[7] = (INT32)h7;
	h[8] = (INT32)h8;
	h[9] = (INT32)h9;
}

VOID FENeg
(
	_In_ PBYTE h,
	_In_ PBYTE f
)
{
	INT32 f0 = f[0];
	INT32 f1 = f[1];
	INT32 f2 = f[2];
	INT32 f3 = f[3];
	INT32 f4 = f[4];
	INT32 f5 = f[5];
	INT32 f6 = f[6];
	INT32 f7 = f[7];
	INT32 f8 = f[8];
	INT32 f9 = f[9];
	INT32 h0 = -f0;
	INT32 h1 = -f1;
	INT32 h2 = -f2;
	INT32 h3 = -f3;
	INT32 h4 = -f4;
	INT32 h5 = -f5;
	INT32 h6 = -f6;
	INT32 h7 = -f7;
	INT32 h8 = -f8;
	INT32 h9 = -f9;

	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
	h[5] = h5;
	h[6] = h6;
	h[7] = h7;
	h[8] = h8;
	h[9] = h9;
}

VOID FECopy
(
	_In_ PBYTE h,
	_In_ PBYTE f
)
{
	INT32 f0 = f[0];
	INT32 f1 = f[1];
	INT32 f2 = f[2];
	INT32 f3 = f[3];
	INT32 f4 = f[4];
	INT32 f5 = f[5];
	INT32 f6 = f[6];
	INT32 f7 = f[7];
	INT32 f8 = f[8];
	INT32 f9 = f[9];

	h[0] = f0;
	h[1] = f1;
	h[2] = f2;
	h[3] = f3;
	h[4] = f4;
	h[5] = f5;
	h[6] = f6;
	h[7] = f7;
	h[8] = f8;
	h[9] = f9;
}

VOID FEInvert
(
	_In_ PBYTE pOutput,
	_In_ PBYTE z
)
{
	INT32 t0[10];
	INT32 t1[10];
	INT32 t2[10];
	INT32 t3[10];
	int i;

	FESq(t0, z);
	for (i = 1; i < 1; ++i) {
		FESq(t0, t0);
	}

	FESq(t1, t0);

	for (i = 1; i < 2; ++i) {
		FESq(t1, t1);
	}

	FEMul(t1, z, t1);
	FEMul(t0, t0, t1);
	FESq(t2, t0);

	for (i = 1; i < 1; ++i) {
		FESq(t2, t2);
	}

	FEMul(t1, t1, t2);
	FESq(t2, t1);

	for (i = 1; i < 5; ++i) {
		FESq(t2, t2);
	}

	FEMul(t1, t2, t1);
	FESq(t2, t1);

	for (i = 1; i < 10; ++i) {
		FESq(t2, t2);
	}

	FEMul(t2, t2, t1);
	FESq(t3, t2);

	for (i = 1; i < 20; ++i) {
		FESq(t3, t3);
	}

	FEMul(t2, t3, t2);
	FESq(t2, t2);

	for (i = 1; i < 10; ++i) {
		FESq(t2, t2);
	}

	FEMul(t1, t2, t1);
	FESq(t2, t1);

	for (i = 1; i < 50; ++i) {
		FESq(t2, t2);
	}

	FEMul(t2, t2, t1);
	FESq(t3, t2);

	for (i = 1; i < 100; ++i) {
		FESq(t3, t3);
	}

	FEMul(t2, t3, t2);
	FESq(t2, t2);

	for (i = 1; i < 50; ++i) {
		FESq(t2, t2);
	}

	FEMul(t1, t2, t1);
	FESq(t1, t1);

	for (i = 1; i < 5; ++i) {
		FESq(t1, t1);
	}

	FEMul(pOutput, t1, t0);
}

BOOL FEIsNegative
(
	_In_ PBYTE f
)
{
	BYTE s[32];

	FEToBytes(s, f);

	return s[0] & 1;
}

VOID GESetP2ToZero
(
	_In_ PED25519_GE_P2 h
)
{
	FE0(h->X);
	FE1(h->Y);
	FE1(h->Z);
}

BOOL GEFrombytesNegateVartime
(
	_In_ PED25519_GE_P3 pGeP3,
	_In_ PBYTE s
)
{
	INT32 u[10];
	INT32 v[10];
	INT32 v3[10];
	INT32 vxx[10];
	INT32 check[10];
	INT32 Sqrtm1[] = { -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482 };
	INT32 d[] = { -10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116 };

	FEFromBytes(pGeP3->Y, s);
	FE1(pGeP3->Z);
	FESq(u, pGeP3->Y);
	FEMul(v, u, d);
	FESub(u, u, pGeP3->Z);     /* u = y^2-1 */
	FEAdd(v, v, pGeP3->Z);     /* v = dy^2+1 */
	FESq(v3, v);
	FEMul(v3, v3, v);      /* v3 = v^3 */
	FESq(pGeP3->X, v3);
	FEMul(pGeP3->X, pGeP3->X, v);
	FEMul(pGeP3->X, pGeP3->X, u);  /* x = uv^7 */
	FEPow22523(pGeP3->X, pGeP3->X); /* x = (uv^7)^((q-5)/8) */
	FEMul(pGeP3->X, pGeP3->X, v3);
	FEMul(pGeP3->X, pGeP3->X, u);  /* x = uv^3(uv^7)^((q-5)/8) */
	FESq(vxx, pGeP3->X);
	FEMul(vxx, vxx, v);
	FESub(check, vxx, u);  /* vx^2-u */

	if (FEIsNonZero(check)) {
		FEAdd(check, vxx, u); /* vx^2+u */

		if (FEIsNonZero(check)) {
			return FALSE;
		}

		FEMul(pGeP3->X, pGeP3->X, Sqrtm1);
	}

	if (FEIsNegative(pGeP3->X) == (s[31] >> 7)) {
		FENeg(pGeP3->X, pGeP3->X);
	}

	FEMul(pGeP3->T, pGeP3->X, pGeP3->Y);
	return TRUE;
}

void SCReduce
(
	_In_ PBYTE s
)
{
	INT64 s0 = 2097151 & ((*((PUINT32)(s))) & 0xFFFFFF);
	INT64 s1 = 2097151 & ((*((PUINT32)(s + 2))) >> 5);
	INT64 s2 = 2097151 & (((*((PUINT32)(s + 5))) & 0xFFFFFF) >> 2);
	INT64 s3 = 2097151 & ((*((PUINT32)(s + 7))) >> 7);
	INT64 s4 = 2097151 & ((*((PUINT32)(s + 10))) >> 4);
	INT64 s5 = 2097151 & (((*((PUINT32)(s + 13))) & 0xFFFFFF) >> 1);
	INT64 s6 = 2097151 & ((*((PUINT32)(s + 15))) >> 6);
	INT64 s7 = 2097151 & (((*((PUINT32)(s + 18))) & 0xFFFFFF) >> 3);
	INT64 s8 = 2097151 & ((*((PUINT32)(s + 21))) & 0xFFFFFF);
	INT64 s9 = 2097151 & ((*((PUINT32)(s + 23))) >> 5);
	INT64 s10 = 2097151 & (((*((PUINT32)(s + 26))) & 0xFFFFFF) >> 2);
	INT64 s11 = 2097151 & ((*((PUINT32)(s + 28))) >> 7);
	INT64 s12 = 2097151 & ((*((PUINT32)(s + 31))) >> 4);
	INT64 s13 = 2097151 & (((*((PUINT32)(s + 34))) & 0xFFFFFF) >> 1);
	INT64 s14 = 2097151 & ((*((PUINT32)(s + 36))) >> 6);
	INT64 s15 = 2097151 & (((*((PUINT32)(s + 39))) & 0xFFFFFF) >> 3);
	INT64 s16 = 2097151 & ((*((PUINT32)(s + 42))) & 0xFFFFFF);
	INT64 s17 = 2097151 & ((*((PUINT32)(s + 44))) >> 5);
	INT64 s18 = 2097151 & (((*((PUINT32)(s + 47))) & 0xFFFFFF) >> 2);
	INT64 s19 = 2097151 & ((*((PUINT32)(s + 49))) >> 7);
	INT64 s20 = 2097151 & ((*((PUINT32)(s + 52))) >> 4);
	INT64 s21 = 2097151 & (((*((PUINT32)(s + 55))) & 0xFFFFFF) >> 1);
	INT64 s22 = 2097151 & ((*((PUINT32)(s + 57))) >> 6);
	INT64 s23 = ((*((PUINT32)(s + 60))) >> 3);
	INT64 carry0;
	INT64 carry1;
	INT64 carry2;
	INT64 carry3;
	INT64 carry4;
	INT64 carry5;
	INT64 carry6;
	INT64 carry7;
	INT64 carry8;
	INT64 carry9;
	INT64 carry10;
	INT64 carry11;
	INT64 carry12;
	INT64 carry13;
	INT64 carry14;
	INT64 carry15;
	INT64 carry16;

	s11 += s23 * 666643;
	s12 += s23 * 470296;
	s13 += s23 * 654183;
	s14 -= s23 * 997805;
	s15 += s23 * 136657;
	s16 -= s23 * 683901;
	s23 = 0;
	s10 += s22 * 666643;
	s11 += s22 * 470296;
	s12 += s22 * 654183;
	s13 -= s22 * 997805;
	s14 += s22 * 136657;
	s15 -= s22 * 683901;
	s22 = 0;
	s9 += s21 * 666643;
	s10 += s21 * 470296;
	s11 += s21 * 654183;
	s12 -= s21 * 997805;
	s13 += s21 * 136657;
	s14 -= s21 * 683901;
	s21 = 0;
	s8 += s20 * 666643;
	s9 += s20 * 470296;
	s10 += s20 * 654183;
	s11 -= s20 * 997805;
	s12 += s20 * 136657;
	s13 -= s20 * 683901;
	s20 = 0;
	s7 += s19 * 666643;
	s8 += s19 * 470296;
	s9 += s19 * 654183;
	s10 -= s19 * 997805;
	s11 += s19 * 136657;
	s12 -= s19 * 683901;
	s19 = 0;
	s6 += s18 * 666643;
	s7 += s18 * 470296;
	s8 += s18 * 654183;
	s9 -= s18 * 997805;
	s10 += s18 * 136657;
	s11 -= s18 * 683901;
	s18 = 0;
	carry6 = (s6 + (1 << 20)) >> 21;
	s7 += carry6;
	s6 -= carry6 << 21;
	carry8 = (s8 + (1 << 20)) >> 21;
	s9 += carry8;
	s8 -= carry8 << 21;
	carry10 = (s10 + (1 << 20)) >> 21;
	s11 += carry10;
	s10 -= carry10 << 21;
	carry12 = (s12 + (1 << 20)) >> 21;
	s13 += carry12;
	s12 -= carry12 << 21;
	carry14 = (s14 + (1 << 20)) >> 21;
	s15 += carry14;
	s14 -= carry14 << 21;
	carry16 = (s16 + (1 << 20)) >> 21;
	s17 += carry16;
	s16 -= carry16 << 21;
	carry7 = (s7 + (1 << 20)) >> 21;
	s8 += carry7;
	s7 -= carry7 << 21;
	carry9 = (s9 + (1 << 20)) >> 21;
	s10 += carry9;
	s9 -= carry9 << 21;
	carry11 = (s11 + (1 << 20)) >> 21;
	s12 += carry11;
	s11 -= carry11 << 21;
	carry13 = (s13 + (1 << 20)) >> 21;
	s14 += carry13;
	s13 -= carry13 << 21;
	carry15 = (s15 + (1 << 20)) >> 21;
	s16 += carry15;
	s15 -= carry15 << 21;
	s5 += s17 * 666643;
	s6 += s17 * 470296;
	s7 += s17 * 654183;
	s8 -= s17 * 997805;
	s9 += s17 * 136657;
	s10 -= s17 * 683901;
	s17 = 0;
	s4 += s16 * 666643;
	s5 += s16 * 470296;
	s6 += s16 * 654183;
	s7 -= s16 * 997805;
	s8 += s16 * 136657;
	s9 -= s16 * 683901;
	s16 = 0;
	s3 += s15 * 666643;
	s4 += s15 * 470296;
	s5 += s15 * 654183;
	s6 -= s15 * 997805;
	s7 += s15 * 136657;
	s8 -= s15 * 683901;
	s15 = 0;
	s2 += s14 * 666643;
	s3 += s14 * 470296;
	s4 += s14 * 654183;
	s5 -= s14 * 997805;
	s6 += s14 * 136657;
	s7 -= s14 * 683901;
	s14 = 0;
	s1 += s13 * 666643;
	s2 += s13 * 470296;
	s3 += s13 * 654183;
	s4 -= s13 * 997805;
	s5 += s13 * 136657;
	s6 -= s13 * 683901;
	s13 = 0;
	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;
	carry0 = (s0 + (1 << 20)) >> 21;
	s1 += carry0;
	s0 -= carry0 << 21;
	carry2 = (s2 + (1 << 20)) >> 21;
	s3 += carry2;
	s2 -= carry2 << 21;
	carry4 = (s4 + (1 << 20)) >> 21;
	s5 += carry4;
	s4 -= carry4 << 21;
	carry6 = (s6 + (1 << 20)) >> 21;
	s7 += carry6;
	s6 -= carry6 << 21;
	carry8 = (s8 + (1 << 20)) >> 21;
	s9 += carry8;
	s8 -= carry8 << 21;
	carry10 = (s10 + (1 << 20)) >> 21;
	s11 += carry10;
	s10 -= carry10 << 21;
	carry1 = (s1 + (1 << 20)) >> 21;
	s2 += carry1;
	s1 -= carry1 << 21;
	carry3 = (s3 + (1 << 20)) >> 21;
	s4 += carry3;
	s3 -= carry3 << 21;
	carry5 = (s5 + (1 << 20)) >> 21;
	s6 += carry5;
	s5 -= carry5 << 21;
	carry7 = (s7 + (1 << 20)) >> 21;
	s8 += carry7;
	s7 -= carry7 << 21;
	carry9 = (s9 + (1 << 20)) >> 21;
	s10 += carry9;
	s9 -= carry9 << 21;
	carry11 = (s11 + (1 << 20)) >> 21;
	s12 += carry11;
	s11 -= carry11 << 21;
	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;
	carry0 = s0 >> 21;
	s1 += carry0;
	s0 -= carry0 << 21;
	carry1 = s1 >> 21;
	s2 += carry1;
	s1 -= carry1 << 21;
	carry2 = s2 >> 21;
	s3 += carry2;
	s2 -= carry2 << 21;
	carry3 = s3 >> 21;
	s4 += carry3;
	s3 -= carry3 << 21;
	carry4 = s4 >> 21;
	s5 += carry4;
	s4 -= carry4 << 21;
	carry5 = s5 >> 21;
	s6 += carry5;
	s5 -= carry5 << 21;
	carry6 = s6 >> 21;
	s7 += carry6;
	s6 -= carry6 << 21;
	carry7 = s7 >> 21;
	s8 += carry7;
	s7 -= carry7 << 21;
	carry8 = s8 >> 21;
	s9 += carry8;
	s8 -= carry8 << 21;
	carry9 = s9 >> 21;
	s10 += carry9;
	s9 -= carry9 << 21;
	carry10 = s10 >> 21;
	s11 += carry10;
	s10 -= carry10 << 21;
	carry11 = s11 >> 21;
	s12 += carry11;
	s11 -= carry11 << 21;
	s0 += s12 * 666643;
	s1 += s12 * 470296;
	s2 += s12 * 654183;
	s3 -= s12 * 997805;
	s4 += s12 * 136657;
	s5 -= s12 * 683901;
	s12 = 0;
	carry0 = s0 >> 21;
	s1 += carry0;
	s0 -= carry0 << 21;
	carry1 = s1 >> 21;
	s2 += carry1;
	s1 -= carry1 << 21;
	carry2 = s2 >> 21;
	s3 += carry2;
	s2 -= carry2 << 21;
	carry3 = s3 >> 21;
	s4 += carry3;
	s3 -= carry3 << 21;
	carry4 = s4 >> 21;
	s5 += carry4;
	s4 -= carry4 << 21;
	carry5 = s5 >> 21;
	s6 += carry5;
	s5 -= carry5 << 21;
	carry6 = s6 >> 21;
	s7 += carry6;
	s6 -= carry6 << 21;
	carry7 = s7 >> 21;
	s8 += carry7;
	s7 -= carry7 << 21;
	carry8 = s8 >> 21;
	s9 += carry8;
	s8 -= carry8 << 21;
	carry9 = s9 >> 21;
	s10 += carry9;
	s9 -= carry9 << 21;
	carry10 = s10 >> 21;
	s11 += carry10;
	s10 -= carry10 << 21;

	s[0] = (BYTE)(s0 >> 0);
	s[1] = (BYTE)(s0 >> 8);
	s[2] = (BYTE)((s0 >> 16) | (s1 << 5));
	s[3] = (BYTE)(s1 >> 3);
	s[4] = (BYTE)(s1 >> 11);
	s[5] = (BYTE)((s1 >> 19) | (s2 << 2));
	s[6] = (BYTE)(s2 >> 6);
	s[7] = (BYTE)((s2 >> 14) | (s3 << 7));
	s[8] = (BYTE)(s3 >> 1);
	s[9] = (BYTE)(s3 >> 9);
	s[10] = (BYTE)((s3 >> 17) | (s4 << 4));
	s[11] = (BYTE)(s4 >> 4);
	s[12] = (BYTE)(s4 >> 12);
	s[13] = (BYTE)((s4 >> 20) | (s5 << 1));
	s[14] = (BYTE)(s5 >> 7);
	s[15] = (BYTE)((s5 >> 15) | (s6 << 6));
	s[16] = (BYTE)(s6 >> 2);
	s[17] = (BYTE)(s6 >> 10);
	s[18] = (BYTE)((s6 >> 18) | (s7 << 3));
	s[19] = (BYTE)(s7 >> 5);
	s[20] = (BYTE)(s7 >> 13);
	s[21] = (BYTE)(s8 >> 0);
	s[22] = (BYTE)(s8 >> 8);
	s[23] = (BYTE)((s8 >> 16) | (s9 << 5));
	s[24] = (BYTE)(s9 >> 3);
	s[25] = (BYTE)(s9 >> 11);
	s[26] = (BYTE)((s9 >> 19) | (s10 << 2));
	s[27] = (BYTE)(s10 >> 6);
	s[28] = (BYTE)((s10 >> 14) | (s11 << 7));
	s[29] = (BYTE)(s11 >> 1);
	s[30] = (BYTE)(s11 >> 9);
	s[31] = (BYTE)(s11 >> 17);
}

VOID GESlide
(
	_In_ LPSTR r,
	_In_ PBYTE a
)
{
	INT32 i;
	INT32 b;
	INT32 k;

	for (i = 0; i < 256; ++i) {
		r[i] = 1 & (a[i >> 3] >> (i & 7));
	}

	for (i = 0; i < 256; ++i) {
		if (r[i]) {
			for (b = 1; b <= 6 && i + b < 256; ++b) {
				if (r[i + b]) {
					if (r[i] + (r[i + b] << b) <= 15) {
						r[i] += r[i + b] << b;
						r[i + b] = 0;
					}
					else if (r[i] - (r[i + b] << b) >= -15) {
						r[i] -= r[i + b] << b;

						for (k = i + b; k < 256; ++k) {
							if (!r[k]) {
								r[k] = 1;
								break;
							}

							r[k] = 0;
						}
					}
					else {
						break;
					}
				}
			}
		}
	}
}

VOID GEConvertP3ToCached
(
	_In_ PED25519_GE_CACHED r,
	_In_ PED25519_GE_P3 p
)
{
	INT32 d2[] = { -21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199 };

	FEAdd(r->YplusX, p->Y, p->X);
	FESub(r->YminusX, p->Y, p->X);
	FECopy(r->Z, p->Z);
	FEMul(r->T2d, p->T, d2);
}

VOID G3ConvertP3ToP2
(
	_In_ PED25519_GE_P2 r,
	_In_ PED25519_GE_P3 p
)
{
	FECopy(r->X, p->X);
	FECopy(r->Y, p->Y);
	FECopy(r->Z, p->Z);
}

VOID GEAdd
(
	_In_ PED25519_GE_P1P1 r,
	_In_ PED25519_GE_P3 p,
	_In_ PED25519_GE_CACHED q
)
{
	INT32 t0[10];

	FEAdd(r->X, p->Y, p->X);
	FESub(r->Y, p->Y, p->X);
	FEMul(r->Z, r->X, q->YplusX);
	FEMul(r->Y, r->Y, q->YminusX);
	FEMul(r->T, q->T2d, p->T);
	FEMul(r->X, p->Z, q->Z);
	FEAdd(t0, r->X, r->X);
	FESub(r->X, r->Z, r->Y);
	FEAdd(r->Y, r->Z, r->Y);
	FEAdd(r->Z, t0, r->T);
	FESub(r->T, t0, r->T);
}

VOID GESub
(
	_In_ PED25519_GE_P1P1 r,
	_In_ PED25519_GE_P3 p,
	_In_ PED25519_GE_CACHED q
)
{
	INT32 t0[10];

	FEAdd(r->X, p->Y, p->X);
	FESub(r->Y, p->Y, p->X);
	FEMul(r->Z, r->X, q->YminusX);
	FEMul(r->Y, r->Y, q->YplusX);
	FEMul(r->T, q->T2d, p->T);
	FEMul(r->X, p->Z, q->Z);
	FEAdd(t0, r->X, r->X);
	FESub(r->X, r->Z, r->Y);
	FEAdd(r->Y, r->Z, r->Y);
	FESub(r->Z, t0, r->T);
	FEAdd(r->T, t0, r->T);
}

VOID GEMAdd
(
	_In_ PED25519_GE_P1P1 r,
	_In_ PED25519_GE_P3 p,
	_In_ PED25519_GE_PRECOMP q
) {
	INT32 t0[10];

	FEAdd(r->X, p->Y, p->X);
	FESub(r->Y, p->Y, p->X);
	FEMul(r->Z, r->X, q->yplusx);
	FEMul(r->Y, r->Y, q->yminusx);
	FEMul(r->T, q->xy2d, p->T);
	FEAdd(t0, p->Z, p->Z);
	FESub(r->X, r->Z, r->Y);
	FEAdd(r->Y, r->Z, r->Y);
	FEAdd(r->Z, t0, r->T);
	FESub(r->T, t0, r->T);
}

VOID GEMSub
(
	_In_ PED25519_GE_P1P1 r,
	_In_ PED25519_GE_P3 p,
	_In_ PED25519_GE_PRECOMP q
) {
	INT32 t0[10];

	FEAdd(r->X, p->Y, p->X);
	FESub(r->Y, p->Y, p->X);
	FEMul(r->Z, r->X, q->yminusx);
	FEMul(r->Y, r->Y, q->yplusx);
	FEMul(r->T, q->xy2d, p->T);
	FEAdd(t0, p->Z, p->Z);
	FESub(r->X, r->Z, r->Y);
	FEAdd(r->Y, r->Z, r->Y);
	FESub(r->Z, t0, r->T);
	FEAdd(r->T, t0, r->T);
}

VOID GEConvertP1P1ToP3
(
	_In_ PED25519_GE_P3 r,
	_In_ PED25519_GE_P1P1 p
)
{
	FEMul(r->X, p->X, p->T);
	FEMul(r->Y, p->Y, p->Z);
	FEMul(r->Z, p->Z, p->T);
	FEMul(r->T, p->X, p->Y);
}

VOID GEConvertP1P1ToP2
(
	_In_ PED25519_GE_P2 r,
	_In_ PED25519_GE_P1P1 p
)
{
	FEMul(r->X, p->X, p->T);
	FEMul(r->Y, p->Y, p->Z);
	FEMul(r->Z, p->Z, p->T);
}

VOID GEDoubleP2
(
	_In_ PED25519_GE_P1P1 r,
	_In_ PED25519_GE_P2 p
)
{
	INT32 t0[10];

	FESq(r->X, p->X);
	FESq(r->Z, p->Y);
	FESq2(r->T, p->Z);
	FEAdd(r->Y, p->X, p->Y);
	FESq(t0, r->Y);
	FEAdd(r->Y, r->Z, r->X);
	FESub(r->Z, r->Z, r->X);
	FESub(r->X, t0, r->Y);
	FESub(r->T, r->T, r->Z);
}


VOID GEDoubleP3
(
	_In_ PED25519_GE_P1P1 r,
	_In_ PED25519_GE_P3 p
)
{
	ED25519_GE_P2 q;

	G3ConvertP3ToP2(&q, p);
	GEDoubleP2(r, &q);
}

VOID GEDoubleScalarMultVarTime(
	_In_ PED25519_GE_P2 r,
	_In_ PBYTE a,
	_In_ PED25519_GE_P3 A,
	_In_ PBYTE b
)
{
	CHAR aslide[256];
	CHAR bslide[256];
	ED25519_GE_CACHED Ai[8]; /* A,3A,5A,7A,9A,11A,13A,15A */
	ED25519_GE_P1P1 t;
	ED25519_GE_P3 u;
	ED25519_GE_P3 A2;
	INT32 i;

	ED25519_GE_PRECOMP Bi[8] = {
	{
		{ 25967493, -14356035, 29566456, 3660896, -12694345, 4014787, 27544626, -11754271, -6079156, 2047605 },
		{ -12545711, 934262, -2722910, 3049990, -727428, 9406986, 12720692, 5043384, 19500929, -15469378 },
		{ -8738181, 4489570, 9688441, -14785194, 10184609, -12363380, 29287919, 11864899, -24514362, -4438546 },
	},
	{
		{ 15636291, -9688557, 24204773, -7912398, 616977, -16685262, 27787600, -14772189, 28944400, -1550024 },
		{ 16568933, 4717097, -11556148, -1102322, 15682896, -11807043, 16354577, -11775962, 7689662, 11199574 },
		{ 30464156, -5976125, -11779434, -15670865, 23220365, 15915852, 7512774, 10017326, -17749093, -9920357 },
	},
	{
		{ 10861363, 11473154, 27284546, 1981175, -30064349, 12577861, 32867885, 14515107, -15438304, 10819380 },
		{ 4708026, 6336745, 20377586, 9066809, -11272109, 6594696, -25653668, 12483688, -12668491, 5581306 },
		{ 19563160, 16186464, -29386857, 4097519, 10237984, -4348115, 28542350, 13850243, -23678021, -15815942 },
	},
	{
		{ 5153746, 9909285, 1723747, -2777874, 30523605, 5516873, 19480852, 5230134, -23952439, -15175766 },
		{ -30269007, -3463509, 7665486, 10083793, 28475525, 1649722, 20654025, 16520125, 30598449, 7715701 },
		{ 28881845, 14381568, 9657904, 3680757, -20181635, 7843316, -31400660, 1370708, 29794553, -1409300 },
	},
	{
		{ -22518993, -6692182, 14201702, -8745502, -23510406, 8844726, 18474211, -1361450, -13062696, 13821877 },
		{ -6455177, -7839871, 3374702, -4740862, -27098617, -10571707, 31655028, -7212327, 18853322, -14220951 },
		{ 4566830, -12963868, -28974889, -12240689, -7602672, -2830569, -8514358, -10431137, 2207753, -3209784 },
	},
	{
		{ -25154831, -4185821, 29681144, 7868801, -6854661, -9423865, -12437364, -663000, -31111463, -16132436 },
		{ 25576264, -2703214, 7349804, -11814844, 16472782, 9300885, 3844789, 15725684, 171356, 6466918 },
		{ 23103977, 13316479, 9739013, -16149481, 817875, -15038942, 8965339, -14088058, -30714912, 16193877 },
	},
	{
		{ -33521811, 3180713, -2394130, 14003687, -16903474, -16270840, 17238398, 4729455, -18074513, 9256800 },
		{ -25182317, -4174131, 32336398, 5036987, -21236817, 11360617, 22616405, 9761698, -19827198, 630305 },
		{ -13720693, 2639453, -24237460, -7406481, 9494427, -5774029, -6554551, -15960994, -2449256, -14291300 },
	},
	{
		{ -3151181, -5046075, 9282714, 6866145, -31907062, -863023, -18940575, 15033784, 25105118, -7894876 },
		{ -24326370, 15950226, -31801215, -14592823, -11662737, -5090925, 1573892, -2625887, 2198790, -15804619 },
		{ -3099351, 10324967, -2241613, 7453183, -5446979, -2735503, -13812022, -16236442, -32461234, -12290683 },
	},
	};

	GESlide(aslide, a);
	GESlide(bslide, b);
	GEConvertP3ToCached(&Ai[0], A);
	GEDoubleP3(&t, A);
	GEConvertP1P1ToP3(&A2, &t);
	GEAdd(&t, &A2, &Ai[0]);
	GEConvertP1P1ToP3(&u, &t);
	GEConvertP3ToCached(&Ai[1], &u);
	GEAdd(&t, &A2, &Ai[1]);
	GEConvertP1P1ToP3(&u, &t);
	GEConvertP3ToCached(&Ai[2], &u);
	GEAdd(&t, &A2, &Ai[2]);
	GEConvertP1P1ToP3(&u, &t);
	GEConvertP3ToCached(&Ai[3], &u);
	GEAdd(&t, &A2, &Ai[3]);
	GEConvertP1P1ToP3(&u, &t);
	GEConvertP3ToCached(&Ai[4], &u);
	GEAdd(&t, &A2, &Ai[4]);
	GEConvertP1P1ToP3(&u, &t);
	GEConvertP3ToCached(&Ai[5], &u);
	GEAdd(&t, &A2, &Ai[5]);
	GEConvertP1P1ToP3(&u, &t);
	GEConvertP3ToCached(&Ai[6], &u);
	GEAdd(&t, &A2, &Ai[6]);
	GEConvertP1P1ToP3(&u, &t);
	GEConvertP3ToCached(&Ai[7], &u);
	GESetP2ToZero(r);

	for (i = 255; i >= 0; --i) {
		if (aslide[i] || bslide[i]) {
			break;
		}
	}

	for (; i >= 0; --i) {
		GEDoubleP2(&t, r);
		if (aslide[i] > 0) {
			GEConvertP1P1ToP3(&u, &t);
			GEAdd(&t, &u, &Ai[aslide[i] / 2]);
		}
		else if (aslide[i] < 0) {
			GEConvertP1P1ToP3(&u, &t);
			GESub(&t, &u, &Ai[(-aslide[i]) / 2]);
		}

		if (bslide[i] > 0) {
			GEConvertP1P1ToP3(&u, &t);
			GEMAdd(&t, &u, &Bi[bslide[i] / 2]);
		}
		else if (bslide[i] < 0) {
			GEConvertP1P1ToP3(&u, &t);
			GEMSub(&t, &u, &Bi[(-bslide[i]) / 2]);
		}

		GEConvertP1P1ToP2(r, &t);
	}
}

VOID GEToBytes
(
	_In_ PBYTE s,
	_In_ PED25519_GE_P2 h
)
{
	INT32 recip[10];
	INT32 x[10];
	INT32 y[10];

	FEInvert(recip, h->Z);
	FEMul(x, h->X, recip);
	FEMul(y, h->Y, recip);
	FEToBytes(s, y);
	s[31] ^= FEIsNegative(x) << 7;
}

BOOL ConstTimeEqual
(
	_In_ PBYTE x,
	_In_ PBYTE y
)
{
	BOOL r = 0;
	DWORD i = 0;

	r = x[0] ^ y[0];
	for (i = 1; i < 32; i++) {
		r |= x[i] ^ y[i];
	}

	return !r;
}

BOOL ED25519Verify
(
	_In_ PBYTE pSignature,
	_In_ PBYTE pMessage,
	_In_ DWORD cbMessage,
	_In_ PBYTE pPublicKey
)
{
	PBYTE pHashDigest = NULL;
	PBYTE pTempBuffer = NULL;
	DWORD cbTempBuffer = 0;
	BOOL Result = FALSE;
	ED25519_GE_P3 A;
	ED25519_GE_P2 R;
	BYTE Checker[32];

	RtlSecureZeroMemory(&A, sizeof(A));
	RtlSecureZeroMemory(&R, sizeof(R));
	RtlSecureZeroMemory(Checker, sizeof(Checker));
	if (GEFrombytesNegateVartime(&A, pPublicKey)) {
		goto CLEANUP;
	}

	pTempBuffer = ALLOC((ED25519_SIGNATURE_SIZE / 2) + X25519_KEY_SIZE + cbMessage);
	memcpy(pTempBuffer, pSignature, ED25519_SIGNATURE_SIZE / 2);
	cbTempBuffer += (ED25519_SIGNATURE_SIZE / 2);
	memcpy(pTempBuffer + cbTempBuffer, pPublicKey, X25519_KEY_SIZE);
	cbTempBuffer += X25519_KEY_SIZE;
	memcpy(pTempBuffer + cbTempBuffer, pMessage, cbMessage);
	cbTempBuffer += cbMessage;
	pHashDigest = ComputeSHA512(pTempBuffer, cbTempBuffer);
	if (pHashDigest == NULL) {
		goto CLEANUP;
	}

	SCReduce(pHashDigest);
	GEDoubleScalarMultVarTime(&R, pHashDigest, &A, pSignature + (ED25519_SIGNATURE_SIZE / 2));
	GEToBytes(Checker, &R);
	if (ConstTimeEqual(Checker, pSignature)) {
		Result = TRUE;
	}

CLEANUP:
	if (pTempBuffer != NULL) {
		FREE(pTempBuffer);
	}

	if (pHashDigest != NULL) {
		FREE(pHashDigest);
	}

	return Result;
}