#pragma once

#define CHACHA20_KEY_SIZE (32)
#define CHACHA20_NONCE_SIZE (12)

VOID Chacha20Poly1305Encrypt
(
    _In_ PBYTE pKey,
    _In_ PBYTE pNonce,
    _In_ PBYTE pMessage,
    _In_ DWORD cbMessage,
    _Out_ PBYTE pCipherText
);

VOID Chacha20Poly1305Decrypt
(
    _In_ PBYTE pKey,
    _In_ PBYTE pNonce,
    _In_ PBYTE pCipherText,
    _In_ DWORD cbMessage,
    _Out_ PBYTE pPlainText
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