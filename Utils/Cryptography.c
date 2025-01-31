#include "pch.h"

#define QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);
#define U32TO8_LITTLE(p, v) (((UINT32*)(p))[0] = U32TO32_LITTLE(v))
#define AGE_FILEKEY_SIZE (16)
#define STREAM_NONCE_SIZE (16)

typedef struct _CHACHA20POLY1305_CONTEXT
{
    POLY1305_CTX PolyCtx;
    UINT32 Input[16];
} CHACHA20POLY1305_CONTEXT, * PCHACHA20POLY1305_CONTEXT;

typedef struct _POLY1305_STATE {
    BYTE Buffer[16];
    SIZE_T Leftover;
    UINT16 r[10];
    UINT16 h[10];
    UINT16 Pad[8];
    BYTE Final;
} POLY1305_STATE, *PPOLY1305_STATE;

typedef struct _AGE_HEADER {
    PSTANZA pStanza;
    PBYTE pMac;
} AGE_HEADER, *PAGE_HEADER;

VOID HChaCha20
(
	_In_ PUINT32 pInput,
	_Out_ PBYTE pCipher
)
{
	UINT32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
	DWORD i;

	x0 = pInput[0];
	x1 = pInput[1];
	x2 = pInput[2];
	x3 = pInput[3];
	x4 = pInput[4];
	x5 = pInput[5];
	x6 = pInput[6];
	x7 = pInput[7];
	x8 = pInput[8];
	x9 = pInput[9];
	x10 = pInput[10];
	x11 = pInput[11];
	x12 = pInput[12];
	x13 = pInput[13];
	x14 = pInput[14];
	x15 = pInput[15];

	for (i = 20; i > 0; i -= 2) {
		QUARTERROUND(x0, x4, x8, x12)
		QUARTERROUND(x1, x5, x9, x13)
		QUARTERROUND(x2, x6, x10, x14)
		QUARTERROUND(x3, x7, x11, x15)
		QUARTERROUND(x0, x5, x10, x15)
		QUARTERROUND(x1, x6, x11, x12)
		QUARTERROUND(x2, x7, x8, x13)
		QUARTERROUND(x3, x4, x9, x14)
	}

	U32TO8_LITTLE(pCipher + 0, x0);
	U32TO8_LITTLE(pCipher + 4, x1);
	U32TO8_LITTLE(pCipher + 8, x2);
	U32TO8_LITTLE(pCipher + 12, x3);
	U32TO8_LITTLE(pCipher + 16, x12);
	U32TO8_LITTLE(pCipher + 20, x13);
	U32TO8_LITTLE(pCipher + 24, x14);
	U32TO8_LITTLE(pCipher + 28, x15);
}

VOID Chacha20KeyInit
(
	_In_ PUINT32 pInput,
	_In_ PBYTE pKey,
	_In_ DWORD dwKeyBits
)
{
	LPSTR lpConstant = NULL;
	CHAR szSigma[] = "expand 32-byte k";
	CHAR szTau[] = "expand 16-byte k";

	pInput[4] = U8TO32_LITTLE(pKey + 0);
	pInput[5] = U8TO32_LITTLE(pKey + 4);
	pInput[6] = U8TO32_LITTLE(pKey + 8);
	pInput[7] = U8TO32_LITTLE(pKey + 12);
	if (dwKeyBits == 256) {
		pKey += 16;
		lpConstant = szSigma;
	}
	else {
		lpConstant = szTau;
	}

	pInput[8] = U8TO32_LITTLE(pKey + 0);
	pInput[9] = U8TO32_LITTLE(pKey + 4);
	pInput[10] = U8TO32_LITTLE(pKey + 8);
	pInput[11] = U8TO32_LITTLE(pKey + 12);
	pInput[0] = U8TO32_LITTLE(lpConstant + 0);
	pInput[1] = U8TO32_LITTLE(lpConstant + 4);
	pInput[2] = U8TO32_LITTLE(lpConstant + 8);
	pInput[3] = U8TO32_LITTLE(lpConstant + 12);
}

VOID Chacha20IvInit
(
	_In_ PUINT32 pInput,
	_In_ PBYTE pIv
)
{
	pInput[12] = 0;
	pInput[13] = 0;
	pInput[14] = U8TO32_LITTLE(pIv + 0);
	pInput[15] = U8TO32_LITTLE(pIv + 4);
}

void Chacha20Encrypt
(
    _In_ PUINT32 pInput,
    _In_ PBYTE pMessage,
    _Out_ PBYTE pCipherText,
    _In_ DWORD cbMessage
)
{
    UINT32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
    UINT32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
    PBYTE pCTarget;
    BYTE Tmp[64] = { 0 };
    int i;

    if (cbMessage == 0) {
        return;
    }

    j0 = pInput[0];
    j1 = pInput[1];
    j2 = pInput[2];
    j3 = pInput[3];
    j4 = pInput[4];
    j5 = pInput[5];
    j6 = pInput[6];
    j7 = pInput[7];
    j8 = pInput[8];
    j9 = pInput[9];
    j10 = pInput[10];
    j11 = pInput[11];
    j12 = pInput[12];
    j13 = pInput[13];
    j14 = pInput[14];
    j15 = pInput[15];

    for (;;) {
        if (cbMessage < 64) {
            for (i = 0; i < cbMessage; ++i) {
                Tmp[i] = pMessage[i];
            }

            pMessage = Tmp;
            pCTarget = pCipherText;
            pCipherText = Tmp;
        }

        x0 = j0;
        x1 = j1;
        x2 = j2;
        x3 = j3;
        x4 = j4;
        x5 = j5;
        x6 = j6;
        x7 = j7;
        x8 = j8;
        x9 = j9;
        x10 = j10;
        x11 = j11;
        x12 = j12;
        x13 = j13;
        x14 = j14;
        x15 = j15;
        for (i = 20; i > 0; i -= 2) {
            QUARTERROUND(x0, x4, x8, x12)
                QUARTERROUND(x1, x5, x9, x13)
                QUARTERROUND(x2, x6, x10, x14)
                QUARTERROUND(x3, x7, x11, x15)
                QUARTERROUND(x0, x5, x10, x15)
                QUARTERROUND(x1, x6, x11, x12)
                QUARTERROUND(x2, x7, x8, x13)
                QUARTERROUND(x3, x4, x9, x14)
        }
        x0 = PLUS(x0, j0);
        x1 = PLUS(x1, j1);
        x2 = PLUS(x2, j2);
        x3 = PLUS(x3, j3);
        x4 = PLUS(x4, j4);
        x5 = PLUS(x5, j5);
        x6 = PLUS(x6, j6);
        x7 = PLUS(x7, j7);
        x8 = PLUS(x8, j8);
        x9 = PLUS(x9, j9);
        x10 = PLUS(x10, j10);
        x11 = PLUS(x11, j11);
        x12 = PLUS(x12, j12);
        x13 = PLUS(x13, j13);
        x14 = PLUS(x14, j14);
        x15 = PLUS(x15, j15);

        x0 = XOR(x0, U8TO32_LITTLE(pMessage + 0));
        x1 = XOR(x1, U8TO32_LITTLE(pMessage + 4));
        x2 = XOR(x2, U8TO32_LITTLE(pMessage + 8));
        x3 = XOR(x3, U8TO32_LITTLE(pMessage + 12));
        x4 = XOR(x4, U8TO32_LITTLE(pMessage + 16));
        x5 = XOR(x5, U8TO32_LITTLE(pMessage + 20));
        x6 = XOR(x6, U8TO32_LITTLE(pMessage + 24));
        x7 = XOR(x7, U8TO32_LITTLE(pMessage + 28));
        x8 = XOR(x8, U8TO32_LITTLE(pMessage + 32));
        x9 = XOR(x9, U8TO32_LITTLE(pMessage + 36));
        x10 = XOR(x10, U8TO32_LITTLE(pMessage + 40));
        x11 = XOR(x11, U8TO32_LITTLE(pMessage + 44));
        x12 = XOR(x12, U8TO32_LITTLE(pMessage + 48));
        x13 = XOR(x13, U8TO32_LITTLE(pMessage + 52));
        x14 = XOR(x14, U8TO32_LITTLE(pMessage + 56));
        x15 = XOR(x15, U8TO32_LITTLE(pMessage + 60));

        j12 = PLUSONE(j12);
        if (!j12) {
            j13 = PLUSONE(j13);
        }

        U32TO8_LITTLE(pCipherText + 0, x0);
        U32TO8_LITTLE(pCipherText + 4, x1);
        U32TO8_LITTLE(pCipherText + 8, x2);
        U32TO8_LITTLE(pCipherText + 12, x3);
        U32TO8_LITTLE(pCipherText + 16, x4);
        U32TO8_LITTLE(pCipherText + 20, x5);
        U32TO8_LITTLE(pCipherText + 24, x6);
        U32TO8_LITTLE(pCipherText + 28, x7);
        U32TO8_LITTLE(pCipherText + 32, x8);
        U32TO8_LITTLE(pCipherText + 36, x9);
        U32TO8_LITTLE(pCipherText + 40, x10);
        U32TO8_LITTLE(pCipherText + 44, x11);
        U32TO8_LITTLE(pCipherText + 48, x12);
        U32TO8_LITTLE(pCipherText + 52, x13);
        U32TO8_LITTLE(pCipherText + 56, x14);
        U32TO8_LITTLE(pCipherText + 60, x15);

        if (cbMessage <= 64) {
            if (cbMessage < 64) {
                for (i = 0; i < cbMessage; ++i) {
                    pCTarget[i] = pCipherText[i];
                }
            }

            pInput[12] = j12;
            pInput[13] = j13;
            return;
        }

        cbMessage -= 64;
        pCipherText += 64;
        pMessage += 64;
    }
}

static UINT16 U8TO16
(
    _In_ PBYTE p
)
{
    return (((unsigned short)(p[0] & 0xff)) | ((unsigned short)(p[1] & 0xff) << 8));
}

static UINT32 U8TOU32(const PBYTE p)
{
    return (((UINT32)(p[0] & 0xff)) |
        ((UINT32)(p[1] & 0xff) << 8) |
        ((UINT32)(p[2] & 0xff) << 16) |
        ((UINT32)(p[3] & 0xff) << 24));
}

static VOID U32TO8
(
    _Out_ PBYTE p,
    _In_ UINT32 v
)
{
    p[0] = (BYTE)((v) & 0xff);
    p[1] = (BYTE)((v >> 8) & 0xff);
    p[2] = (BYTE)((v >> 16) & 0xff);
    p[3] = (BYTE)((v >> 24) & 0xff);
}

VOID Poly1305Blocks
(
    _In_ PPOLY1305_CTX pCtx,
    _In_ PBYTE pBuffer,
    _In_ DWORD cbBuffer,
    _In_ DWORD dwPadBit
)
{
    UINT32 r0, r1, r2, r3;
    UINT32 s1, s2, s3;
    UINT32 h0, h1, h2, h3, h4, c;
    UINT64 d0, d1, d2, d3;

    r0 = pCtx->r[0];
    r1 = pCtx->r[1];
    r2 = pCtx->r[2];
    r3 = pCtx->r[3];

    s1 = r1 + (r1 >> 2);
    s2 = r2 + (r2 >> 2);
    s3 = r3 + (r3 >> 2);

    h0 = pCtx->h[0];
    h1 = pCtx->h[1];
    h2 = pCtx->h[2];
    h3 = pCtx->h[3];
    h4 = pCtx->h[4];

    while (cbBuffer >= POLY1305_BLOCK_SIZE) {
        /* h += m[i] */
        h0 = (UINT32)(d0 = (UINT64)h0 + U8TOU32(pBuffer + 0));
        h1 = (UINT32)(d1 = (UINT64)h1 + (d0 >> 32) + U8TOU32(pBuffer + 4));
        h2 = (UINT32)(d2 = (UINT64)h2 + (d1 >> 32) + U8TOU32(pBuffer + 8));
        h3 = (UINT32)(d3 = (UINT64)h3 + (d2 >> 32) + U8TOU32(pBuffer + 12));
        h4 += (UINT32)(d3 >> 32) + dwPadBit;

        /* h *= r "%" p, where "%" stands for "partial remainder" */
        d0 = ((UINT64)h0 * r0) +
            ((UINT64)h1 * s3) +
            ((UINT64)h2 * s2) +
            ((UINT64)h3 * s1);
        d1 = ((UINT64)h0 * r1) +
            ((UINT64)h1 * r0) +
            ((UINT64)h2 * s3) +
            ((UINT64)h3 * s2) +
            (h4 * s1);
        d2 = ((UINT64)h0 * r2) +
            ((UINT64)h1 * r1) +
            ((UINT64)h2 * r0) +
            ((UINT64)h3 * s3) +
            (h4 * s2);
        d3 = ((UINT64)h0 * r3) +
            ((UINT64)h1 * r2) +
            ((UINT64)h2 * r1) +
            ((UINT64)h3 * r0) +
            (h4 * s3);
        h4 = (h4 * r0);

        /* last reduction step: */
        /* a) h4:h0 = h4<<128 + d3<<96 + d2<<64 + d1<<32 + d0 */
        h0 = (UINT32)d0;
        h1 = (UINT32)(d1 += d0 >> 32);
        h2 = (UINT32)(d2 += d1 >> 32);
        h3 = (UINT32)(d3 += d2 >> 32);
        h4 += (UINT32)(d3 >> 32);
        /* b) (h4:h0 += (h4:h0>>130) * 5) %= 2^130 */
        c = (h4 >> 2) + (h4 & ~3U);
        h4 &= 3;
        h0 += c;
        h1 += (c = CONSTANT_TIME_CARRY(h0, c));
        h2 += (c = CONSTANT_TIME_CARRY(h1, c));
        h3 += (c = CONSTANT_TIME_CARRY(h2, c));
        h4 += CONSTANT_TIME_CARRY(h3, c);
        /*
         * Occasional overflows to 3rd bit of h4 are taken care of
         * "naturally". If after this point we end up at the top of
         * this loop, then the overflow bit will be accounted for
         * in next iteration. If we end up in poly1305_emit, then
         * comparison to modulus below will still count as "carry
         * into 131st bit", so that properly reduced value will be
         * picked in conditional move.
         */

        pBuffer += POLY1305_BLOCK_SIZE;
        cbBuffer -= POLY1305_BLOCK_SIZE;
    }

    pCtx->h[0] = h0;
    pCtx->h[1] = h1;
    pCtx->h[2] = h2;
    pCtx->h[3] = h3;
    pCtx->h[4] = h4;
}

VOID Poly1305Update
(
    _In_ PPOLY1305_CTX pCtx,
    _In_ PBYTE pBuffer,
    _In_ DWORD cbBuffer
)
{
    DWORD dwRem, dwNum;

    if ((dwNum = pCtx->dwNum)) {
        dwRem = POLY1305_BLOCK_SIZE - dwNum;
        if (cbBuffer >= dwRem) {
            memcpy(pCtx->Data + dwNum, pBuffer, dwRem);
            Poly1305Blocks(pCtx, pCtx->Data, POLY1305_BLOCK_SIZE, 1);
            pBuffer += dwRem;
            cbBuffer -= dwRem;
        }
        else {
            memcpy(pCtx->Data + dwNum, pBuffer, cbBuffer);
            pCtx->dwNum = dwNum + cbBuffer;
            return;
        }
    }

    dwRem = cbBuffer % POLY1305_BLOCK_SIZE;
    cbBuffer -= dwRem;

    if (cbBuffer >= POLY1305_BLOCK_SIZE) {
        Poly1305Blocks(pCtx, pBuffer, cbBuffer, 1);
        pBuffer += cbBuffer;
    }

    if (dwRem) {
        memcpy(pCtx->Data, pBuffer, dwRem);
    }

    pCtx->dwNum = dwRem;
}

VOID Poly1305Emit
(
    _In_ PPOLY1305_CTX pCtx,
    _In_ PBYTE pMac,
    _In_ PUINT32 pNonce
)
{
    UINT32 h0, h1, h2, h3, h4;
    UINT32 g0, g1, g2, g3, g4;
    UINT64 t;
    UINT32 mask;

    h0 = pCtx->h[0];
    h1 = pCtx->h[1];
    h2 = pCtx->h[2];
    h3 = pCtx->h[3];
    h4 = pCtx->h[4];

    /* compare to modulus by computing h + -p */
    g0 = (UINT32)(t = (UINT64)h0 + 5);
    g1 = (UINT32)(t = (UINT64)h1 + (t >> 32));
    g2 = (UINT32)(t = (UINT64)h2 + (t >> 32));
    g3 = (UINT32)(t = (UINT64)h3 + (t >> 32));
    g4 = h4 + (UINT32)(t >> 32);

    /* if there was carry into 131st bit, h3:h0 = g3:g0 */
    mask = 0 - (g4 >> 2);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;

    /* mac = (h + nonce) % (2^128) */
    h0 = (UINT32)(t = (UINT64)h0 + pNonce[0]);
    h1 = (UINT32)(t = (UINT64)h1 + (t >> 32) + pNonce[1]);
    h2 = (UINT32)(t = (UINT64)h2 + (t >> 32) + pNonce[2]);
    h3 = (UINT32)(t = (UINT64)h3 + (t >> 32) + pNonce[3]);

    U32TO8(pMac + 0, h0);
    U32TO8(pMac + 4, h1);
    U32TO8(pMac + 8, h2);
    U32TO8(pMac + 12, h3);
}

VOID Poly1305Finish
(
    PPOLY1305_CTX pCtx,
    PBYTE pMac
)
{
    DWORD dwNum;

    if ((dwNum = pCtx->dwNum)) {
        pCtx->Data[dwNum++] = 1;
        while (dwNum < POLY1305_BLOCK_SIZE) {
            pCtx->Data[dwNum++] = 0;
        }

        Poly1305Blocks(pCtx, pCtx->Data, POLY1305_BLOCK_SIZE, 0);
    }

    Poly1305Emit(pCtx, pMac, pCtx->Nonce);
}

PPOLY1305_CTX Poly1305Init
(
    _In_ PBYTE pKey
)
{
    PPOLY1305_CTX pCtx = ALLOC(sizeof(POLY1305_CTX));

    pCtx->Nonce[0] = U8TOU32(&pKey[16]);
    pCtx->Nonce[1] = U8TOU32(&pKey[20]);
    pCtx->Nonce[2] = U8TOU32(&pKey[24]);
    pCtx->Nonce[3] = U8TOU32(&pKey[28]);

    pCtx->dwNum = 0;

    pCtx->h[0] = 0;
    pCtx->h[1] = 0;
    pCtx->h[2] = 0;
    pCtx->h[3] = 0;
    pCtx->h[4] = 0;

    pCtx->r[0] = U8TOU32(&pKey[0]) & 0x0fffffff;
    pCtx->r[1] = U8TOU32(&pKey[4]) & 0x0ffffffc;
    pCtx->r[2] = U8TOU32(&pKey[8]) & 0x0ffffffc;
    pCtx->r[3] = U8TOU32(&pKey[12]) & 0x0ffffffc;

    return pCtx;
}

PBYTE Poly1305Padding
(
    _In_ PBYTE pBuffer,
    _In_ DWORD cbBuffer
)
{
    DWORD dwNewSize = 0;

    if ((cbBuffer % POLY1305_BLOCK_SIZE) == 0) {
        dwNewSize = cbBuffer;
    }
    else {
        dwNewSize = cbBuffer - (cbBuffer % POLY1305_BLOCK_SIZE) + POLY1305_BLOCK_SIZE;
    }

    if (dwNewSize == cbBuffer) {
        return NULL;
    }

    PBYTE pResult = ALLOC(dwNewSize);
    memcpy(pResult, pBuffer, cbBuffer);
    return pResult;
}

PCHACHA20POLY1305_CONTEXT Chacha20Poly1305Init
(
    _In_ PBYTE pKey,
    _In_ PBYTE pNonce
)
{
    PCHACHA20POLY1305_CONTEXT Result = NULL;
    BYTE FirstBlock[64] = { 0 };
    BYTE SubKey[32] = { 0 };
    PPOLY1305_CTX pPolyCtx = NULL;

    Result = ALLOC(sizeof(CHACHA20POLY1305_CONTEXT));
    Chacha20KeyInit(Result->Input, pKey, 256);
    Result->Input[13] = U8TO32_LITTLE(pNonce + 0);
    Result->Input[14] = U8TO32_LITTLE(pNonce + 4);
    Result->Input[15] = U8TO32_LITTLE(pNonce + 8);

    Chacha20Encrypt(Result->Input, FirstBlock, FirstBlock, sizeof(FirstBlock));

    pPolyCtx = Poly1305Init(FirstBlock);
    memcpy(&Result->PolyCtx, pPolyCtx, sizeof(POLY1305_CTX));
    FREE(pPolyCtx);
    return Result;
}

VOID Chacha20Poly1305Encrypt
(
    _In_ PBYTE pKey,
    _In_ PBYTE pNonce,
    _In_ PBYTE pMessage,
    _In_ DWORD cbMessage,
    _In_ PBYTE pAAD,
    _In_ DWORD cbAAD,
    _Out_ PBYTE* pCipherText,
    _Out_ PDWORD pCipherTextSize
)
{
    PCHACHA20POLY1305_CONTEXT pCtx = NULL;
    PBYTE pResult = ALLOC(cbMessage + POLY1305_BLOCK_SIZE + CHACHA20_NONCE_SIZE);
    PBYTE pMac = NULL;
    UINT64 uTemp = 0;
    DWORD dwTemp = 0;
    PBYTE pTempBuffer = NULL;
    DWORD dwPos = 0;
    DWORD cbPaddedAAD = 0;
    DWORD cbPaddeMsg = 0;

    if ((cbAAD % POLY1305_BLOCK_SIZE) == 0) {
        cbPaddedAAD = cbAAD;
    }
    else {
        cbPaddedAAD = cbAAD - (cbAAD % POLY1305_BLOCK_SIZE) + POLY1305_BLOCK_SIZE;
    }

    if ((cbMessage % POLY1305_BLOCK_SIZE) == 0) {
        cbPaddeMsg = cbMessage;
    }
    else {
        cbPaddeMsg = cbMessage - (cbMessage % POLY1305_BLOCK_SIZE) + POLY1305_BLOCK_SIZE;
    }

    pCtx = Chacha20Poly1305Init(pKey, pNonce);
    Chacha20Encrypt(pCtx->Input, pMessage, pResult + dwPos, cbMessage);
    pTempBuffer = ALLOC(cbPaddeMsg + cbPaddedAAD + (sizeof(UINT64) * 2));
    if (pAAD != NULL && cbPaddedAAD > 0) {
        memcpy(pTempBuffer, pAAD, cbAAD);
        dwPos += cbPaddedAAD;
    }

    memcpy(pTempBuffer + dwPos, pResult, cbMessage);
    dwPos += cbPaddeMsg;
    if (cbAAD != 0) {
        memcpy(pTempBuffer + dwPos, &cbAAD, sizeof(cbAAD));
    }

    dwPos += sizeof(UINT64);
    memcpy(pTempBuffer + dwPos, &cbMessage, sizeof(cbMessage));
    Poly1305Update(&pCtx->PolyCtx, pTempBuffer, dwPos + sizeof(UINT64));
    pMac = ALLOC(POLY1305_MAC_SIZE);
    Poly1305Finish(&pCtx->PolyCtx, pMac);
    memcpy(pResult + cbMessage, pMac, POLY1305_MAC_SIZE);
    FREE(pMac);
    FREE(pCtx);
    FREE(pTempBuffer);
    *pCipherText = pResult;
    *pCipherTextSize = cbMessage + POLY1305_MAC_SIZE;
    return;
}

VOID Chacha20Poly1305Decrypt
(
    _In_ PBYTE pKey,
    _In_ PBYTE pNonce,
    _In_ PBYTE pMessage,
    _In_ DWORD cbMessage,
    _In_ PBYTE pAAD,
    _In_ DWORD cbAAD,
    _Out_ PBYTE* pCipherText,
    _Out_ PDWORD pCipherTextSize
)
{
    PCHACHA20POLY1305_CONTEXT pCtx = NULL;
    PBYTE pResult = ALLOC(cbMessage + POLY1305_BLOCK_SIZE);
    PBYTE pMac = NULL;
    UINT64 uTemp = 0;
    DWORD dwTemp = 0;
    PBYTE pTempBuffer = NULL;
    DWORD dwPos = 0;
    DWORD cbPaddedAAD = 0;
    DWORD cbPaddeMsg = 0;

    if ((cbAAD % POLY1305_BLOCK_SIZE) == 0) {
        cbPaddedAAD = cbAAD;
    }
    else {
        cbPaddedAAD = cbAAD - (cbAAD % POLY1305_BLOCK_SIZE) + POLY1305_BLOCK_SIZE;
    }

    if ((cbMessage % POLY1305_BLOCK_SIZE) == 0) {
        cbPaddeMsg = cbMessage;
    }
    else {
        cbPaddeMsg = cbMessage - (cbMessage % POLY1305_BLOCK_SIZE) + POLY1305_BLOCK_SIZE;
    }

    pCtx = Chacha20Poly1305Init(pKey, pNonce);
    Chacha20Encrypt(pCtx->Input, pMessage, pResult, cbMessage);
    pTempBuffer = ALLOC(cbPaddeMsg + cbPaddedAAD + (sizeof(UINT64) * 2));
    if (pAAD != NULL && cbPaddedAAD > 0) {
        memcpy(pTempBuffer, pAAD, cbAAD);
        dwPos += cbPaddedAAD;
    }

    memcpy(pTempBuffer + dwPos, pMessage, cbMessage);
    dwPos += cbPaddeMsg;
    if (cbAAD != 0) {
        memcpy(pTempBuffer + dwPos, &cbAAD, sizeof(cbAAD));
    }

    dwPos += sizeof(UINT64);
    memcpy(pTempBuffer + dwPos, &cbMessage, sizeof(cbMessage));
    Poly1305Update(&pCtx->PolyCtx, pTempBuffer, dwPos + sizeof(UINT64));
    pMac = ALLOC(POLY1305_MAC_SIZE);
    Poly1305Finish(&pCtx->PolyCtx, pMac);
    memcpy(pResult + cbMessage, pMac, POLY1305_MAC_SIZE);
    FREE(pMac);
    FREE(pCtx);
    FREE(pTempBuffer);
    *pCipherText = pResult;
    *pCipherTextSize = cbMessage + POLY1305_MAC_SIZE;
    return;
}

BOOL Chacha20Poly1305CompareConstTime
(
    _In_ PBYTE pTag,
    _In_ PBYTE pMac
)
{
    DWORD i = 0;
    DWORD dwResult = 0;

    for (i = 0; i < POLY1305_MAC_SIZE; i++) {
        dwResult |= (pTag[i] ^ pMac[i]);
    }

    return dwResult == 0;
}

PBUFFER Chacha20Poly1305DecryptAndVerify
(
    _In_ PBYTE pKey,
    _In_ PBYTE pNonce,
    _In_ PBYTE pCipherText,
    _In_ DWORD cbCipherText,
    _In_ PBYTE pAAD,
    _In_ DWORD cbAAD
)
{
    PBYTE pMac = &pCipherText[cbCipherText - POLY1305_MAC_SIZE];
    PBYTE pTag = NULL;
    PBUFFER pResult = NULL;

    pResult = ALLOC(sizeof(BUFFER));
    Chacha20Poly1305Decrypt(pKey, pNonce, pCipherText, cbCipherText - POLY1305_MAC_SIZE, pAAD, cbAAD, &pResult->pBuffer, &pResult->cbBuffer);
    if (pResult->pBuffer == NULL || pResult->cbBuffer == 0) {
        FreeBuffer(pResult);
        return NULL;
    }

    pResult->cbBuffer -= POLY1305_MAC_SIZE;
    pTag = &pResult->pBuffer[pResult->cbBuffer];
    if (!Chacha20Poly1305CompareConstTime(pTag, pMac)) {
        FreeBuffer(pResult);
        return NULL;
    }

    return pResult;
}

PBYTE H
(
    _In_ PBYTE pX,
    _In_ DWORD cbX,
    _In_ PBYTE pY,
    _In_ DWORD cbY
)
{
    PBYTE pResult;
    DWORD cbBuffer = (cbX + cbY);
    PBYTE pBuffer = ALLOC(cbBuffer);

    if (pX != NULL && cbX > 0) {
        memcpy(pBuffer, pX, cbX);
    }

    if (pY != NULL && cbY > 0) {
        memcpy(pBuffer + cbX, pY, cbY);
    }

    pResult = ComputeSHA256(pBuffer, cbBuffer);
    FREE(pBuffer);
    return pResult;
}

PBYTE GenerateHmacSHA256
(
    _In_ PBYTE pKey,
    _In_ DWORD cbKey,
    _In_ PBYTE pData,
    _In_ DWORD cbData
)
{
    BYTE k[SHA256_BLOCK_SIZE];
    BYTE k_ipad[SHA256_BLOCK_SIZE];
    BYTE k_opad[SHA256_BLOCK_SIZE];
    PBYTE pIHash;
    PBYTE pOHash;
    DWORD i = 0;

    RtlSecureZeroMemory(k, sizeof(k));
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k_ipad[i] = 0x36;
        k_opad[i] = 0x5c;
    }

    if (cbKey > SHA256_BLOCK_SIZE) {
        ComputeSHA256(pKey, cbKey);
    }
    else {
        memcpy(k, pKey, cbKey);
    }

    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k_ipad[i] ^= k[i];
        k_opad[i] ^= k[i];
    }

    pIHash = H(k_ipad, sizeof(k_ipad), pData, cbData);
    pOHash = H(k_opad, sizeof(k_opad), pIHash, SHA256_HASH_SIZE);
    FREE(pIHash);
    return pOHash;
}

static UINT32 Bech32PolymodStep(UINT32 uPre) {
    BYTE b = uPre >> 25;
    return ((uPre & 0x1FFFFFF) << 5) ^
        (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
        (-((b >> 1) & 1) & 0x26508e6dUL) ^
        (-((b >> 2) & 1) & 0x1ea119faUL) ^
        (-((b >> 3) & 1) & 0x3d4233ddUL) ^
        (-((b >> 4) & 1) & 0x2a1462b3UL);
}

UINT32 Bech32FinalConstant
(
    _In_ Bech32Encoding enc
)
{
    if (enc == BECH32_ENCODING_BECH32) {
        return 1;
    }

    if (enc == BECH32_ENCODING_BECH32M) {
        return 0x2bc830a3;
    }
}

VOID Bech32Encode
(
    LPSTR lpOutput,
    DWORD dwOutputSize,
    PBYTE pHrp,
    PBYTE pData,
    DWORD cbData,
    Bech32Encoding EncodingAlg
)
{
    UINT32 chk = 1;
    DWORD i = 0;
    CHAR Bech32Charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    while (pHrp[i] != 0) {
        int ch = pHrp[i];
        if (ch < 33 || ch > 126) {
            return;
        }

        if (ch >= 'A' && ch <= 'Z') {
            return;
        }

        chk = Bech32PolymodStep(chk) ^ (ch >> 5);
        ++i;
    }

    if (i + 7 + cbData > dwOutputSize) {
        return;
    }

    chk = Bech32PolymodStep(chk);
    while (*pHrp != 0) {
        chk = Bech32PolymodStep(chk) ^ (*pHrp & 0x1f);
        *(lpOutput++) = *(pHrp++);
    }

    *(lpOutput++) = '1';
    for (i = 0; i < cbData; ++i) {
        if (*pData >> 5) {
            return;
        }

        chk = Bech32PolymodStep(chk) ^ (*pData);
        *(lpOutput++) = Bech32Charset[*(pData++)];
    }

    for (i = 0; i < 6; ++i) {
        chk = Bech32PolymodStep(chk);
    }

    chk ^= Bech32FinalConstant(EncodingAlg);
    for (i = 0; i < 6; ++i) {
        *(lpOutput++) = Bech32Charset[(chk >> ((5 - i) * 5)) & 0x1f];
    }

    *lpOutput = 0;
    return;
}

PBYTE Bech32ExpandHrp
(
    _In_ PBYTE pHrp,
    _Out_ PDWORD pOutputSize
)
{
    *pOutputSize = lstrlenA(pHrp) * 2 + 1;
    PBYTE pResult = ALLOC(*pOutputSize);
    DWORD i = 0;

    for (i = 0; i < lstrlenA(pHrp); i++) {
        pResult[i] = pHrp[i] >> 5;
		pResult[i + lstrlenA(pHrp) + 1] = pHrp[i] & 31;
    }

    return pResult;
}

UINT32 Bech32Polymod
(
	_In_ PBYTE pBuffer,
	_In_ DWORD cbBuffer
)
{
	UINT32 uChecksum = 1;
	DWORD i = 0;
	DWORD j = 0;
    UINT32 uTop = 0;
    UINT32 Generator[] = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };

	for (i = 0; i < cbBuffer; i++) {
        uTop = uChecksum >> 25;
        uChecksum = ((uChecksum & 0x1FFFFFF) << 5) ^ pBuffer[i];
        for (j = 0; j < 5; j++) {
            if (((uTop >> j) & 1)) {
                uChecksum ^= Generator[j];
            }
            else {
                uChecksum ^= 0;
            }
        }
	}

	return uChecksum;
}

BOOL Bech32VerifyChecksum
(
    _In_ LPSTR lpHrp,
    _In_ PBYTE pData,
    _In_ DWORD cbData
)
{
    PBYTE pExpandedHrp = NULL;
    DWORD cbExpandedHrp = 0;
    PBYTE pTempArray = NULL;
    DWORD i = 0;
    BOOL bResult = FALSE;

    pExpandedHrp = Bech32ExpandHrp(lpHrp, &cbExpandedHrp);
    pTempArray = ALLOC(cbExpandedHrp + cbData);
    for (i = 0; i < cbExpandedHrp; i++) {
		pTempArray[i] = pExpandedHrp[i];
	}

    for (i = 0; i < cbData; i++) {
		pTempArray[i + cbExpandedHrp] = pData[i];
	}

    FREE(pExpandedHrp);
    bResult = Bech32Polymod(pTempArray, cbExpandedHrp + cbData) == 1;
    FREE(pTempArray);
	return bResult;
}

PBYTE Bech32ConvertBits
(
    _In_ PBYTE pData,
    _In_ DWORD cbData,
    _In_ DWORD dwFromBits,
    _In_ DWORD dwToBits,
    _In_ BOOL bPad,
    _Out_ PDWORD pOutputSize
)
{
    DWORD dwAcc = 0;
    BYTE bBits = 0;
    PBYTE pResult = NULL;
    DWORD dwMaxv = ((1 << dwToBits) - 1) & 0xFF;
    DWORD i = 0;
    DWORD j = 0;

    pResult = ALLOC((cbData * dwFromBits + dwToBits - 1) / dwToBits);
    for (i = 0; i < cbData; i++) {
        if (pData[i] >> dwFromBits) {
            FREE(pResult);
			return NULL;
		}

        dwAcc = (dwAcc << dwFromBits) | pData[i];
        bBits = (bBits + dwFromBits) & 0xFF;
		while (bBits >= dwToBits) {
            bBits -= dwToBits;
            pResult[j++] = ((dwAcc >> bBits) & 0xFF) & dwMaxv;
		}
    }

    if (bPad) {
        if (bBits) {
            pResult[j++] = ((dwAcc << (dwToBits - bBits)) & 0xFF) & dwMaxv;
        }
    }
    else if (bBits > dwFromBits || (((dwAcc << (dwToBits - bBits)) & 0xFF) & dwMaxv)) {
        FREE(pResult);
        return NULL;
    }

    *pOutputSize = j;
    return pResult;
}


Bech32Encoding Bech32Decode
(
    _Out_ LPSTR lpHrp,
    _Out_ PBYTE* pOutput,
    _Out_ PDWORD pOutputSize,
    _In_ LPSTR lpInput
)
{
    DWORD i = 0;
    DWORD j = 0;
    DWORD cbInput = lstrlenA(lpInput);
    DWORD dwHrpLength;
    UINT32 ch = 0;
    PBYTE pData = NULL;
    DWORD cbData = 0;
    DWORD dwPos = 0;
    BYTE szCharSet[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    BOOL IsInCharset = FALSE;
    DWORD dwIdx = 0;
    LPSTR lpTemp = NULL;

    lpTemp = DuplicateStrA(lpInput, 0);
    for (i = 0; i < cbInput; i++) {
        if (lpTemp[i] < 33 || lpTemp[i] > 126) {
            FREE(lpTemp);
			return BECH32_ENCODING_NONE;
		}

        if (lpTemp[i] >= 'A' && lpTemp[i] <= 'Z') {
            lpTemp[i] += 32;
		}
    }

    for (i = 0; i < cbInput; i++) {
        if (lpTemp[i] == '1') {
            break;
        }

        lpHrp[i] = lpTemp[i];
    }

    if (i < 1 || i + 7 > cbInput) {
        SecureZeroMemory(lpHrp, i);
        FREE(lpTemp);
		return BECH32_ENCODING_NONE;
	}

    dwPos = ++i;
    if (cbInput < 8 || cbInput > cbInput) {
        FREE(lpTemp);
        return BECH32_ENCODING_NONE;
    }

    cbData = cbInput - dwPos;
    pData = ALLOC(cbData);
    for (i = dwPos; i < cbInput; i++) {
        for (j = 0; j < lstrlenA(szCharSet); j++) {
			if (lpTemp[i] == szCharSet[j]) {
				pData[i - dwPos] = j;
				break;
			}
		}

        for (j = 0; j < lstrlenA(szCharSet); j++) {
            if (lpTemp[i] == szCharSet[j]) {
				IsInCharset = TRUE;
				break;
			}
        }

        if (!IsInCharset) {
            FREE(pData);
            FREE(lpTemp);
            return BECH32_ENCODING_NONE;
        }
    }

    if (!Bech32VerifyChecksum(lpHrp, pData, cbData)) {
        FREE(pData);
        FREE(lpTemp);
        return BECH32_ENCODING_NONE;
    }

    cbData -= 6;
    *pOutput = Bech32ConvertBits(pData, cbData, 5, 8, FALSE, pOutputSize);
    FREE(pData);
    FREE(lpTemp);

    return BECH32_ENCODING_BECH32;
}

LPSTR AgeHeaderMarshal
(
    _In_ PBYTE pFileKey,
    _In_ DWORD cbFileKey,
    _In_ PAGE_HEADER pHdr
)
{
    PBYTE pHmacKey = NULL;
    CHAR szInfo[] = "header";
    DWORD cbHmacKey = 32;
    CHAR szIntro[] = "age-encryption.org/v1\n";
    CHAR szStanzaPrefix[] = "->";
    CHAR szFooterPrefix[] = "---";
    LPSTR lpHmacData = NULL;
    DWORD i = 0;
    LPSTR lpBodyBase64 = NULL;
    LPSTR lpTemp = NULL;
    DWORD cbBodyBase64 = 0;
    LPSTR lpResult = NULL;
    LPSTR lpTempBase64 = NULL;

    pHmacKey = HKDFGenerate(NULL, 0, pFileKey, cbFileKey, szInfo, lstrlenA(szInfo), cbHmacKey);
    if (pHmacKey == NULL) {
        goto CLEANUP;
    }

    lpHmacData = ALLOC(0x200);
    wsprintfA(lpHmacData, "%s%s %s", szIntro, szStanzaPrefix, pHdr->pStanza->lpType);
    for (i = 0; i < pHdr->pStanza->dwArgc; i++) {
        lstrcatA(lpHmacData, " ");
        lstrcatA(lpHmacData, pHdr->pStanza->pArgs[i]);
    }

    lstrcatA(lpHmacData, "\n");
    lpBodyBase64 = Base64Encode(pHdr->pStanza->pBody, pHdr->pStanza->cbBody, TRUE);
    cbBodyBase64 = lstrlenA(lpBodyBase64);
    lpTemp = ALLOC(cbBodyBase64 + (cbBodyBase64 / 64) + 1);
    for (i = 0; i < cbBodyBase64 / 64; i++) {
        memcpy(lpTemp + (i * 65), lpBodyBase64 + (i * 64), 64);
        lstrcatA(lpTemp, "\n");
    }

    lstrcatA(lpTemp, lpBodyBase64 + (i * 64));
    lstrcatA(lpHmacData, lpTemp);
    lstrcatA(lpHmacData, "\n");
    lstrcatA(lpHmacData, szFooterPrefix);
    pHdr->pMac = GenerateHmacSHA256(pHmacKey, cbHmacKey, lpHmacData, lstrlenA(lpHmacData));
    lstrcatA(lpHmacData, " ");
    if (pHdr->pMac == NULL) {
        goto CLEANUP;
    }

    lpTempBase64 = Base64Encode(pHdr->pMac, SHA256_HASH_SIZE, TRUE);
    if (lpTempBase64 == NULL) {
        goto CLEANUP;
    }

    lpResult = ALLOC(lstrlenA(lpHmacData) + lstrlenA(lpTempBase64) + 2);
    lstrcpyA(lpResult, lpHmacData);
    lstrcatA(lpResult, lpTempBase64);
    lstrcatA(lpResult, "\n");
CLEANUP:
    FREE(lpHmacData);
    FREE(lpTempBase64);
    FREE(pHmacKey);
    FREE(lpBodyBase64);
    FREE(lpTemp);

    return lpResult;
}

PBYTE AgeEncrypt
(
    _In_ LPSTR pRecipientPubKey,
    _In_ PBYTE pPlainText,
    _In_ DWORD cbPlainText,
    _Out_ PDWORD pOutputSize
)
{
    PBYTE pFileKey = NULL;
    PAGE_HEADER pHdr = NULL;
    PBYTE pHeader = NULL;
    PBYTE pNonce = NULL;
    PBYTE pStreamKey = NULL;
    CHAR szInfo[] = "payload";
    DWORD cbHeader = 0;
    CHAR szAgeMsgPrefix[] = "age-encryption.org/v1\n-> X25519 ";
    DWORD dwPos = 0;
    DWORD i = 0;
    PBYTE pDecodedRecipientPubKey = NULL;
    DWORD cbDecodedRecipientPubKey = 0;
    CHAR szHrp[0x10];
    PBYTE pEncryptedChunk = NULL;
    DWORD cbEncryptedChunk = 0;
    BOOL IsSuccess = FALSE;

    pFileKey = GenRandomBytes(AGE_FILEKEY_SIZE);
    if (pFileKey == NULL) {
        goto CLEANUP;
    }

    pHdr = ALLOC(sizeof(AGE_HEADER));
    RtlSecureZeroMemory(szHrp, sizeof(szHrp));
    if (Bech32Decode(szHrp, &pDecodedRecipientPubKey, &cbDecodedRecipientPubKey, pRecipientPubKey) == BECH32_ENCODING_NONE || lstrcmpA(szHrp, "age")) {
        goto CLEANUP;
    }

    pHdr->pStanza = AgeRecipientWrap(pFileKey, AGE_FILEKEY_SIZE, pDecodedRecipientPubKey);
    if (pHdr->pStanza == NULL) {
        goto CLEANUP;
    }

    pHeader = AgeHeaderMarshal(pFileKey, AGE_FILEKEY_SIZE, pHdr);
    if (pHeader == NULL) {
        goto CLEANUP;
    }

    lstrcpyA(pHeader, pHeader + lstrlenA(szAgeMsgPrefix));
    pNonce = GenRandomBytes(STREAM_NONCE_SIZE);
    if (pNonce == NULL) {
        goto CLEANUP;
    }

    cbHeader = lstrlenA(pHeader);
    pHeader = REALLOC(pHeader, cbHeader + STREAM_NONCE_SIZE);
    memcpy(pHeader + cbHeader, pNonce, STREAM_NONCE_SIZE);
    cbHeader += STREAM_NONCE_SIZE;
    pStreamKey = HKDFGenerate(pNonce, STREAM_NONCE_SIZE, pFileKey, AGE_FILEKEY_SIZE, szInfo, lstrlenA(szInfo), CHACHA20_KEY_SIZE);
    if (pStreamKey == NULL) {
        goto CLEANUP;
    }

    RtlSecureZeroMemory(pNonce, STREAM_NONCE_SIZE);
    while (cbPlainText > STREAM_CHUNK_SIZE) {
        cbPlainText -= STREAM_CHUNK_SIZE;
        Chacha20Poly1305Encrypt(pStreamKey, pNonce, pPlainText + dwPos, STREAM_CHUNK_SIZE, NULL, 0, &pEncryptedChunk, &cbEncryptedChunk);
        if (pEncryptedChunk == NULL || cbEncryptedChunk == 0) {
            goto CLEANUP;
        }

        pHeader = REALLOC(pHeader, cbHeader + cbEncryptedChunk);
        memcpy(pHeader + cbHeader, pEncryptedChunk, cbEncryptedChunk);
        cbHeader += cbEncryptedChunk;
        FREE(pEncryptedChunk);
        pEncryptedChunk = NULL;
        cbEncryptedChunk = 0;
        dwPos += STREAM_CHUNK_SIZE;
        i = CHACHA20_NONCE_SIZE - 2;
        while (i >= 0) {
            pNonce[i]++;
            if (pNonce[i] != 0) {
                break;
            }
            else if (i == 0) {
                ExitProcess(-1);
            }

            i--;
        }
    }

    pNonce[CHACHA20_NONCE_SIZE - 1] = 1;
    Chacha20Poly1305Encrypt(pStreamKey, pNonce, pPlainText + dwPos, cbPlainText, NULL, 0, &pEncryptedChunk, &cbEncryptedChunk);
    if (pEncryptedChunk == NULL || cbEncryptedChunk == 0) {
        goto CLEANUP;
    }

    pHeader = REALLOC(pHeader, cbHeader + cbEncryptedChunk);
    memcpy(pHeader + cbHeader, pEncryptedChunk, cbEncryptedChunk);
    cbHeader += cbEncryptedChunk;
    if (pOutputSize != NULL) {
        *pOutputSize = cbHeader;
    }

    IsSuccess = TRUE;
CLEANUP:
    if (!IsSuccess && pHeader != NULL) {
        FREE(pHeader);
        pHeader = NULL;
    }

    FREE(pNonce);
    FREE(pDecodedRecipientPubKey);
    if (pHdr != NULL) {
        FreeStanza(pHdr->pStanza);
        FREE(pHdr->pMac);
        FREE(pHdr);
    }

    FREE(pFileKey);
    FREE(pEncryptedChunk);

    return pHeader;
}

PBYTE AgeKeyExToServer
(
    _In_ LPSTR lpRecipientPubKey,
    _In_ LPSTR lpPrivateKey,
    _In_ LPSTR lpPublicKey,
    _In_ PBYTE pPlainText,
    _In_ DWORD cbPlainText,
    _Out_opt_ PDWORD pcbCipherText
)
{
    DWORD cbOutput = 0;
    PBYTE pCipherText = NULL;
    PBYTE pPrivateDigest = NULL;
    PBYTE pPublicDigest = NULL;
    PBYTE pPrivateHmac = NULL;
    PBYTE pTemp = NULL;
    PBYTE pResult = NULL;

    pPrivateDigest = ComputeSHA256(lpPrivateKey, lstrlenA(lpPrivateKey));
    pPrivateHmac = GenerateHmacSHA256(pPrivateDigest, SHA256_HASH_SIZE, pPlainText, cbPlainText);
    pTemp = ALLOC(cbPlainText + SHA256_HASH_SIZE);
    memcpy(pTemp, pPrivateHmac, SHA256_HASH_SIZE);
    memcpy(pTemp + SHA256_HASH_SIZE, pPlainText, cbPlainText);
    pCipherText = AgeEncrypt(lpRecipientPubKey, pTemp, cbPlainText + SHA256_HASH_SIZE, &cbOutput);
    if (pCipherText == NULL) {
        goto CLEANUP;
    }

    pPublicDigest = ComputeSHA256(lpPublicKey, lstrlenA(lpPublicKey));
    pResult = ALLOC(cbOutput + SHA256_HASH_SIZE);
    memcpy(pResult, pPublicDigest, SHA256_HASH_SIZE);
    memcpy(pResult + SHA256_HASH_SIZE, pCipherText, cbOutput);
    cbOutput += SHA256_HASH_SIZE;
    if (pcbCipherText != NULL) {
        *pcbCipherText = cbOutput;
    }

CLEANUP:
    FREE(pPrivateDigest);
    FREE(pPrivateHmac);
    FREE(pTemp);
    FREE(pCipherText);
    FREE(pPublicDigest);

    return pResult;
}