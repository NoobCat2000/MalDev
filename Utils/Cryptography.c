#include "pch.h"

#define U8C(v) (v##U)
#define U16C(v) (v##U)
#define U32C(v) (v##U)
#define U64C(v) (v##ULL)
#define U8V(v) ((UINT8)(v) & U8C(0xFF))
#define U16V(v) ((UINT16)(v) & U16C(0xFFFF))
#define U32V(v) ((UINT32)(v) & U32C(0xFFFFFFFF))
#define U64V(v) ((UINT64)(v) & U64C(0xFFFFFFFFFFFFFFFF))
#define U32TO32_LITTLE(v) (v)
#define ROTL8(v, n) \
  (U8V((v) << (n)) | ((v) >> (8 - (n))))
#define ROTL16(v, n) \
  (U16V((v) << (n)) | ((v) >> (16 - (n))))
#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))
#define ROTL64(v, n) \
  (U64V((v) << (n)) | ((v) >> (64 - (n))))
#define U8TO32_LITTLE(p) U32TO32_LITTLE(((UINT32*)(p))[0])
#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))
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
    BYTE pOtk[32];
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
	_In_ DWORD dwKeyBits,
	_In_ DWORD dwIvBits
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



PBYTE Poly1305Mac
(
    _In_ PBYTE pMac,
    _In_ DWORD cbMac,
    _In_ PBYTE pKey
)
{

}

VOID Poly1305Update
(
    _In_ PCHACHA20POLY1305_CONTEXT pCtx,
    _In_ PBYTE pMessage,
    _In_ DWORD cbMessage,
    _In_ PBYTE pAAD,
    _In_ DWORD cbAAD
)
{
    PBYTE pMacData = NULL;
    DWORD cbMac = 0;
    DWORD dwPos = 0;

    cbMac = cbAAD - (cbAAD % 16) + 16;
    dwPos = cbMac;
    cbMac += cbMessage - (cbMessage % 16) + 32;
    pMacData = ALLOC(cbMac);
    memcpy(pMacData, pAAD, cbAAD);
    memcpy(pMacData + dwPos, pMessage, cbMessage);
    dwPos += cbMessage - (cbMessage % 16) + 16;
    memcpy(pMacData + dwPos, &cbAAD, sizeof(cbAAD));
    dwPos += 8;
    memcpy(pMacData + dwPos, &cbMessage, sizeof(cbMessage));

}

VOID Poly1305Init
(
    _In_ PCHACHA20POLY1305_CONTEXT pCtx,
    _In_ PBYTE pKey
)
{
    PPOLY1305_STATE st = (PPOLY1305_STATE)pCtx;
    UINT16 t0, t1, t2, t3, t4, t5, t6, t7;
    SIZE_T i;

    t0 = U8TO16(&pKey[0]); st->r[0] = (t0) & 0x1fff;
    t1 = U8TO16(&pKey[2]); st->r[1] = ((t0 >> 13) | (t1 << 3)) & 0x1fff;
    t2 = U8TO16(&pKey[4]); st->r[2] = ((t1 >> 10) | (t2 << 6)) & 0x1f03;
    t3 = U8TO16(&pKey[6]); st->r[3] = ((t2 >> 7) | (t3 << 9)) & 0x1fff;
    t4 = U8TO16(&pKey[8]); st->r[4] = ((t3 >> 4) | (t4 << 12)) & 0x00ff;
    st->r[5] = ((t4 >> 1)) & 0x1ffe;
    t5 = U8TO16(&pKey[10]); st->r[6] = ((t4 >> 14) | (t5 << 2)) & 0x1fff;
    t6 = U8TO16(&pKey[12]); st->r[7] = ((t5 >> 11) | (t6 << 5)) & 0x1f81;
    t7 = U8TO16(&pKey[14]); st->r[8] = ((t6 >> 8) | (t7 << 8)) & 0x1fff;
    st->r[9] = ((t7 >> 5)) & 0x007f;
    for (i = 0; i < 10; i++) {
        st->h[i] = 0;
    }

    for (i = 0; i < 8; i++) {
        st->Pad[i] = U8TO16(&pKey[16 + (2 * i)]);
    }

    st->Leftover = 0;
    st->Final = 0;
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

	Result = ALLOC(sizeof(CHACHA20POLY1305_CONTEXT));
	if (Result == NULL) {
		return NULL;
	}

	Chacha20KeyInit(Result->Input, pKey, 256, 16);
    Result->Input[13] = U8TO32_LITTLE(pNonce + 0);
    Result->Input[14] = U8TO32_LITTLE(pNonce + 4);
    Result->Input[15] = U8TO32_LITTLE(pNonce + 8);

    Chacha20Encrypt(Result->Input, FirstBlock, FirstBlock, 64);

    memcpy(Result->pOtk, FirstBlock, 32);
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
    _Out_ PBYTE pCipherText
)
{
    PCHACHA20POLY1305_CONTEXT pCtx = Chacha20Poly1305Init(pKey, pNonce);
    Chacha20Encrypt(pCtx->Input, pMessage, pCipherText, cbMessage);
    Poly1305Update(pCtx, pCipherText, cbMessage, pAAD, cbAAD);
    FREE(pCtx);
}

VOID Chacha20Poly1305Decrypt
(
    _In_ PBYTE pKey,
    _In_ PBYTE pNonce,
    _In_ PBYTE pCipherText,
    _In_ DWORD cbMessage,
    _Out_ PBYTE pPlainText
)
{
    PCHACHA20POLY1305_CONTEXT pCtx = Chacha20Poly1305Init(pKey, pNonce);
    Poly1305Update(pCtx, pCipherText, cbMessage);
    Chacha20Encrypt(pCtx->Input, pCipherText, pPlainText, cbMessage);
    FREE(pCtx);
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
    memset(k_ipad, 0x36, SHA256_BLOCK_SIZE);
    memset(k_opad, 0x5c, SHA256_BLOCK_SIZE);

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
            uChecksum ^= ((uTop >> j) & 1) ? Generator[j] : 0;
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
    DWORD i, j;
    DWORD cbInput = lstrlenA(lpInput);
    DWORD dwHrpLength;
    UINT32 ch = 0;
    PBYTE pData = NULL;
    DWORD cbData = 0;
    DWORD dwPos = 0;
    BYTE szCharSet[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    BOOL IsInCharset = FALSE;
    DWORD dwIdx = 0;

    for (i = 0; i < cbInput; i++) {
        if (lpInput[i] < 33 || lpInput[i] > 126) {
			return BECH32_ENCODING_NONE;
		}

        if (lpInput[i] >= 'A' && lpInput[i] <= 'Z') {
            lpInput[i] += 32;
		}
    }

    for (i = 0; i < cbInput; i++) {
        if (lpInput[i] == '1') {
            break;
        }

        lpHrp[i] = lpInput[i];
    }

    if (i < 1 || i + 7 > cbInput) {
        memset(lpHrp, 0, i);
		return BECH32_ENCODING_NONE;
	}

    dwPos = ++i;
    if (cbInput < 8 || cbInput > cbInput) {
        return BECH32_ENCODING_NONE;
    }

    cbData = cbInput - dwPos;
    pData = ALLOC(cbData);
    for (i = dwPos; i < cbInput; i++) {
        for (j = 0; j < lstrlenA(szCharSet); j++) {
			if (lpInput[i] == szCharSet[j]) {
				pData[i - dwPos] = j;
				break;
			}
		}

        for (j = 0; j < lstrlenA(szCharSet); j++) {
            if (lpInput[i] == szCharSet[j]) {
				IsInCharset = TRUE;
				break;
			}
        }

        if (!IsInCharset) {
            FREE(pData);
            return BECH32_ENCODING_NONE;
        }
    }

    if (!Bech32VerifyChecksum(lpHrp, pData, cbData)) {
        FREE(pData);
        return BECH32_ENCODING_NONE;
    }

    cbData -= 6;
    *pOutput = Bech32ConvertBits(pData, cbData, 5, 8, FALSE, pOutputSize);
    FREE(pData);
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
    LPSTR lpResult = NULL;
    LPSTR lpTempBase64 = NULL;

    pHmacKey = HKDFGenerate(NULL, 0, pFileKey, cbFileKey, szInfo, lstrlenA(szInfo), cbHmacKey);
    if (pHmacKey == NULL) {
        return NULL;
    }

    lpHmacData = ALLOC(0x200);
    sprintf_s(lpHmacData, 0x200, "%s%s%s ", szIntro, szStanzaPrefix, pHdr->pStanza->lpType);

    for (i = 0; i < pHdr->pStanza->dwArgc; i++) {
        lstrcpyA(lpHmacData, pHdr->pStanza->pArgs[i]);
        lstrcpyA(lpHmacData, " ");
    }

    lstrcpyA(lpHmacData, "\n");
    lpBodyBase64 = Base64Encode(pHdr->pStanza->pBody, pHdr->pStanza->cbBody);
    lstrcpyA(lpHmacData, "\n");
    lstrcpyA(lpHmacData, lpBodyBase64);
    FREE(lpBodyBase64);
    lstrcpyA(lpHmacData, "\n");
    lstrcpyA(lpHmacData, szFooterPrefix);
    pHdr->pMac = GenerateHmacSHA256(pHmacKey, cbHmacKey, lpHmacData, lstrlenA(lpHmacData));
    FREE(pHmacKey);
    lpTempBase64 = Base64Encode(pHdr->pMac, SHA256_HASH_SIZE);
    if (lpTempBase64 == NULL) {
        return NULL;
    }

    lpResult = ALLOC(lstrlenA(lpHmacData) + lstrlenA(lpTempBase64) + 2);
    StrCpyA(lpResult, lpHmacData);
    FREE(lpHmacData);
    StrCpyA(lpResult, lpTempBase64);
    FREE(lpTempBase64);
    StrCpyA(lpResult, "\n");
    return lpResult;
}

PBYTE AgeEncrypt
(
    _In_ PBYTE pRecipientPubKey,
    _In_ PBYTE pPlainText,
    _In_ DWORD cbPlainText,
    _Out_ PDWORD pOutputSize
)
{
    PBYTE pFileKey = NULL;
    PAGE_HEADER pHdr = NULL;
    LPSTR lpHeader = NULL;
    PBYTE pNonce = NULL;
    PBYTE pStreamKey = NULL;
    CHAR szInfo = "payload";
    DWORD cbHeader = 0;
    DWORD dwPos = 0;
    DWORD i = 0;
    PBYTE pDecodedRecipientPubKey = NULL;
    DWORD cbDecodedRecipientPubKey = 0;
    CHAR szHrp[0x10];

    pFileKey = GenRandomBytes(AGE_FILEKEY_SIZE);
    if (pFileKey == NULL) {
        goto CLEANUP;
    }

    pHdr = ALLOC(sizeof(AGE_HEADER));
    RtlSecureZeroMemory(szHrp, sizeof(szHrp));
    if (Bech32Decode(szHrp, &pDecodedRecipientPubKey, &cbDecodedRecipientPubKey, pRecipientPubKey) == BECH32_ENCODING_NONE || StrCmpA(szHrp, "age")) {
        goto CLEANUP;
    }

    pHdr->pStanza = AgeRecipientWrap(pFileKey, AGE_FILEKEY_SIZE, pDecodedRecipientPubKey);
    lpHeader = AgeHeaderMarshal(pFileKey, AGE_FILEKEY_SIZE, pHdr);
    if (lpHeader == NULL) {
        FreeStanza(pHdr->pStanza);
        FREE(pHdr->pMac);
        FREE(pHdr);
        FREE(pFileKey);
        return NULL;
    }

    pNonce = GenRandomBytes(STREAM_NONCE_SIZE);
    cbHeader = lstrlenA(lpHeader);
    lpHeader = REALLOC(lpHeader, cbHeader + STREAM_NONCE_SIZE + cbPlainText);
    memcpy(lpHeader + cbHeader, pNonce, STREAM_NONCE_SIZE);
    cbHeader += STREAM_NONCE_SIZE;
    pStreamKey = HKDFGenerate(pNonce, STREAM_NONCE_SIZE, pFileKey, AGE_FILEKEY_SIZE, szInfo, lstrlenA(szInfo), CHACHA20_KEY_SIZE);
    FREE(pNonce);
    pNonce = ALLOC(CHACHA20_NONCE_SIZE);
    while (cbPlainText > STREAM_CHUNK_SIZE) {
        cbPlainText -= STREAM_CHUNK_SIZE;
        Chacha20Poly1305Encrypt(pStreamKey, pNonce, pPlainText + dwPos, STREAM_CHUNK_SIZE, lpHeader + cbHeader + dwPos);
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
    Chacha20Poly1305Encrypt(pStreamKey, pNonce, pPlainText + dwPos, cbPlainText, lpHeader + cbHeader + dwPos);
    /*i = CHACHA20_NONCE_SIZE - 2;
    while (i >= 0) {
        pNonce[i]++;
        if (pNonce[i] != 0) {
            break;
        }
        else if (i == 0) {
            ExitProcess(-1);
        }

        i--;
    }*/

    if (pOutputSize != NULL) {
        *pOutputSize = cbHeader + cbPlainText;
    }

CLEANUP:
    if (pNonce != NULL) {
        FREE(pNonce);
    }

    if (pDecodedRecipientPubKey != NULL) {
        FREE(pDecodedRecipientPubKey);
    }

    if (pHdr != NULL) {
        FreeStanza(pHdr->pStanza);
        FREE(pHdr->pMac);
        FREE(pHdr);
    }

    if (pFileKey != NULL) {
        FREE(pFileKey);
    }

    return lpHeader;
}