#pragma once

#define CHACHA20_KEY_SIZE (32)
#define CHACHA20_NONCE_SIZE (12)
#define STREAM_NONCE_SIZE (16)
#define STREAM_CHUNK_SIZE (65536)
#define POLY1305_BLOCK_SIZE (16)
#define POLY1305_MAC_SIZE (16)
# define CONSTANT_TIME_CARRY(a,b) ( \
         (a ^ ((a ^ b) | ((a - b) ^ b))) >> (sizeof(a) * 8 - 1) \
         )
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
#define ROTR64(v, n) \
  (U64V((v) << (64 - (n))) | ((v) >> (n)))
#define U8TO32_LITTLE(p) U32TO32_LITTLE(((UINT32*)(p))[0])
#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

typedef struct _POLY1305_CTX {
    UINT32 h[5];
    UINT32 r[4];
    UINT32 Nonce[4];
    DWORD dwNum;
    BYTE Data[POLY1305_BLOCK_SIZE];
} POLY1305_CTX, *PPOLY1305_CTX;

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
);

PBUFFER Chacha20Poly1305DecryptAndVerify
(
    _In_ PBYTE pKey,
    _In_ PBYTE pNonce,
    _In_ PBYTE pCipherText,
    _In_ DWORD cbCipherText,
    _In_ PBYTE pAAD,
    _In_ DWORD cbAAD
);

PBYTE GenerateHmacSHA256
(
    _In_ PBYTE pKey,
    _In_ DWORD cbKey,
    _In_ PBYTE pData,
    _In_ DWORD cbData
);

typedef enum {
    BECH32_ENCODING_NONE,
    BECH32_ENCODING_BECH32,
    BECH32_ENCODING_BECH32M
} Bech32Encoding;

VOID Bech32Encode
(
    LPSTR lpOutput,
    DWORD dwOutputSize,
    PBYTE pHrp,
    PBYTE pData,
    DWORD cbData,
    Bech32Encoding EncodingAlg
);

Bech32Encoding Bech32Decode
(
    _Out_ LPSTR lpHrp,
    _Out_ PBYTE* pOutput,
    _Out_ PDWORD pOutputSize,
    _In_ LPSTR lpInput
);

PBYTE AgeEncrypt
(
    _In_ LPSTR pRecipientPubKey,
    _In_ PBYTE pPlainText,
    _In_ DWORD cbPlainText,
    _Out_ PDWORD pOutputSize
);

PBYTE AgeKeyExToServer
(
    _In_ LPSTR lpRecipientPubKey,
    _In_ LPSTR lpPrivateKey,
    _In_ LPSTR lpPublicKey,
    _In_ PBYTE pPlainText,
    _In_ DWORD cbPlainText,
    _Out_opt_ PDWORD pcbCipherText
);

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
);