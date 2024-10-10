#include "pch.h"

POTP_DATA OtpInit
(
	_In_ DWORD dwInterval,
	_In_ UINT64 uCount,
	_In_ DWORD dwDigits,
	_In_ LPSTR lpBase32Secret
)
{
	POTP_DATA pResult = NULL;

	pResult = ALLOC(sizeof(OTP_DATA));
	pResult->dwInterval = dwInterval;
	pResult->uCount = uCount;
	pResult->dwDigits = dwDigits;
	pResult->lpBase32Secret = DuplicateStrA(lpBase32Secret, 0);

	return pResult;
}

PBYTE OtpConvertIntToBytes
(
	_In_ UINT64 uInput
)
{
	PBYTE pResult = NULL;
	DWORD i = 7;

	pResult = ALLOC(sizeof(UINT64));
	while (uInput != 0) {
		pResult[i] = uInput & 0xFF;
		i--;
		uInput >>= 8;
	}

	return pResult;
}

PBYTE OtpBase32Decode
(
	_In_ POTP_DATA pData
)
{
	PBYTE pResult = NULL;
	DWORD dwNumberOfBlocks = 0;
	DWORD i = 0;
	DWORD j = 0;
	DWORD k = 0;
	BYTE BlockValues[8];
	BOOL IsFound = FALSE;
	CHAR szDefaultBase32Chars[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7' };
	CHAR c;

	dwNumberOfBlocks = lstrlenA(pData->lpBase32Secret) / 8;
	pResult = ALLOC(dwNumberOfBlocks * 5);
	for (i = 0; i < dwNumberOfBlocks; i++) {
		SecureZeroMemory(BlockValues, sizeof(BlockValues));
		for (j = 0; j < 8; j++) {
			c = pData->lpBase32Secret[i * 8 + j];
			if (c == '=')
				break;

			IsFound = FALSE;
			for (k = 0; k < _countof(szDefaultBase32Chars); k++) {
				if (c == szDefaultBase32Chars[k]) {
					BlockValues[j] = k;
					IsFound = TRUE;
					break;
				}
			}

			if (!IsFound) {
				if (pResult != NULL) {
					FREE(pResult);
				}

				return NULL;
			}
		}

		pResult[i * 5] = (BlockValues[0] << 3) | (BlockValues[1] >> 2);
		pResult[i * 5 + 1] = (BlockValues[1] << 6) | (BlockValues[2] << 1) | (BlockValues[3] >> 4);
		pResult[i * 5 + 2] = (BlockValues[3] << 4) | (BlockValues[4] >> 1);
		pResult[i * 5 + 3] = (BlockValues[4] << 7) | (BlockValues[5] << 2) | (BlockValues[6] >> 3);
		pResult[i * 5 + 4] = (BlockValues[6] << 5) | BlockValues[7];
	}

	return pResult;
}

UINT64 OtpGenerate
(
	_In_ POTP_DATA pOtpData,
	_In_ UINT64 uInput
)
{
	PBYTE pBytesArray = NULL;
	DWORD cbSecret = 0;
	PBYTE pSecret = NULL;
	PBYTE pHmac = NULL;
	UINT64 uOffset = 0;
	UINT64 uResult = 0;
	UINT64 Powers[] = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 };

	cbSecret = (lstrlenA(pOtpData->lpBase32Secret) / 8) * 5;
	pBytesArray = OtpConvertIntToBytes(uInput / pOtpData->dwInterval);
	pSecret = OtpBase32Decode(pOtpData);
	pHmac = GenerateHmacSHA256(pSecret, cbSecret, pBytesArray, sizeof(UINT64));
	uOffset = pHmac[SHA256_HASH_SIZE - 1] & 0xF;
	uResult = (((pHmac[uOffset] & 0x7F) << 24) | ((pHmac[uOffset + 1] & 0xFF) << 16) | ((pHmac[uOffset + 2] & 0xFF) << 8) | ((pHmac[uOffset + 3] & 0xFF)));
	uResult %= Powers[pOtpData->dwDigits];
CLEANUP:
	if (pBytesArray != NULL) {
		FREE(pBytesArray);
	}

	if (pHmac != NULL) {
		FREE(pHmac);
	}

	if (pSecret != NULL) {
		FREE(pSecret);
	}

	return uResult;
}

UINT64 GetOtpNow
(
	_In_ POTP_DATA pOtpData
)
{
	UINT64 uNow = 0;

	uNow = GetCurrentTimeStamp();
	return OtpGenerate(pOtpData, uNow);
}