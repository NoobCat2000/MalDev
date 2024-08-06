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

PSTANZA X25519RecipientWrap
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

	RtlSecureZeroMemory(Chacha20Nonce, sizeof(Chacha20Nonce));
	pEphemeral = GenRandomBytes(X25519_SCALAR_SIZE);
	pOurPubKey = ALLOC(X25519_SHARED_SIZE);
	pSharedSecret = ALLOC(X25519_SHARED_SIZE);
	ComputeX25519(pOurPubKey, pEphemeral, BasePoint);
	ComputeX25519(pSharedSecret, pEphemeral, pTheirPubKey);
	if (pEphemeral != NULL) {
		FREE(pEphemeral);
	}

	pSalt = ALLOC(2 * X25519_KEY_SIZE);
	memcpy(pSalt, pOurPubKey, X25519_KEY_SIZE);
	if (pOurPubKey != NULL) {
		FREE(pOurPubKey);
	}

	memcpy(pSalt + X25519_KEY_SIZE, pTheirPubKey, X25519_KEY_SIZE);
	pWrappingKey = HKDFGenerate(pSalt, 2 * X25519_KEY_SIZE, pSharedSecret, X25519_SHARED_SIZE, Info, lstrlenA(Info), CHACHA20_KEY_SIZE);
	if (pSharedSecret != NULL) {
		FREE(pSharedSecret);
	}

	if (pSalt != NULL) {
		FREE(pSalt);
	}

	pWrappedKey = ALLOC(cbBuffer);
	Chacha20Poly1305Encrypt(pWrappingKey, Chacha20Nonce, pBuffer, cbBuffer, pWrappedKey);
	if (pWrappingKey != NULL) {
		FREE(pWrappingKey);
	}

	pResult = ALLOC(sizeof(STANZA));
	pResult->lpType = "X25519";
	pResult->pArgs = ALLOC(sizeof(LPSTR));
	pResult->pBody = pWrappedKey;
	return pResult;
}