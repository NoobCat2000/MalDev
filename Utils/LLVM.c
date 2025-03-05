#include "pch.h"

#define DEREF( name )		*(	UINT_PTR	*)	(name)
#define DEREF_64( name )	*(	DWORD64		*)	(name)
#define DEREF_32( name )	*(	DWORD		*)	(name)
#define DEREF_16( name )	*(	WORD		*)	(name)
#define DEREF_8( name )		*(	BYTE		*)	(name)
#define CHAR_BIT      8
#define SEED 0x15
#define NTDLLDLL								0x8511a1b8
#define LdrLoadDll_StrHashed                    0xAC97B4C4

void salsa20_encrypt
(
	unsigned char* key,
	unsigned char nonce[8],
	unsigned char* buf,
	unsigned int buflen
)
{
	unsigned char keystream[64];
	unsigned char n[16] = { 0 };
	unsigned int x[16];
	unsigned int z[16];
	unsigned char t[16] = "expand 16-byte k";

	for (unsigned int i = 0; i < 8; ++i) {
		n[i] = nonce[i];
	}

	for (unsigned int i = 0; i < buflen; ++i) {
		if (i % 64 == 0) {
			n[8] = (i / 64);
			n[9] = (i / 64) >> 8;
			n[10] = (i / 64) >> 16;
			n[11] = (i / 64) >> 24;
			for (unsigned int z = 0; z < 64; z += 20) {
				for (unsigned int j = 0; j < 4; ++j) {
					keystream[z + j] = t[(z / 5) + j];
				}
			}

			for (unsigned int j = 0; j < 16; ++j) {
				keystream[4 + j] = key[j];
				keystream[44 + j] = key[j];
				keystream[24 + j] = n[j];
			}

			for (unsigned int j = 0; j < 16; ++j) {
				x[j] = z[j] = keystream[(4 * j) + 0] + ((unsigned int)keystream[(4 * j) + 1] << 8) + ((unsigned int)keystream[(4 * j) + 2] << 16) + ((unsigned int)keystream[(4 * j) + 3] << 24);
			}

			for (unsigned int j = 0; j < 10; ++j) {
				z[4] = z[4] ^ ((z[0] + z[12]) << 7 | (z[0] + z[12]) >> 25);
				z[8] = z[8] ^ ((z[4] + z[0]) << 9 | (z[4] + z[0]) >> 23);
				z[12] = z[12] ^ ((z[4] + z[8]) << 13 | (z[4] + z[8]) >> 19);
				z[0] = z[0] ^ ((z[12] + z[8]) << 18 | (z[12] + z[8]) >> 14);

				z[9] = z[9] ^ ((z[5] + z[1]) << 7 | (z[5] + z[1]) >> 25);
				z[13] = z[13] ^ ((z[5] + z[9]) << 9 | (z[5] + z[9]) >> 23);
				z[1] = z[1] ^ ((z[13] + z[9]) << 13 | (z[13] + z[9]) >> 19);
				z[5] = z[5] ^ ((z[13] + z[1]) << 18 | (z[13] + z[1]) >> 14);

				z[14] = z[14] ^ ((z[6] + z[10]) << 7 | (z[6] + z[10]) >> 25);
				z[2] = z[2] ^ ((z[14] + z[10]) << 9 | (z[14] + z[10]) >> 23);
				z[6] = z[6] ^ ((z[14] + z[2]) << 13 | (z[14] + z[2]) >> 19);
				z[10] = z[10] ^ ((z[6] + z[2]) << 18 | (z[6] + z[2]) >> 14);

				z[3] = z[3] ^ ((z[15] + z[11]) << 7 | (z[15] + z[11]) >> 25);
				z[7] = z[7] ^ ((z[3] + z[15]) << 9 | (z[3] + z[15]) >> 23);
				z[11] = z[11] ^ ((z[7] + z[3]) << 13 | (z[7] + z[3]) >> 19);
				z[15] = z[15] ^ ((z[11] + z[7]) << 18 | (z[11] + z[7]) >> 14);

				z[1] = z[1] ^ ((z[0] + z[3]) << 7 | (z[0] + z[3]) >> 25);
				z[2] = z[2] ^ ((z[1] + z[0]) << 9 | (z[1] + z[0]) >> 23);
				z[3] = z[3] ^ ((z[2] + z[1]) << 13 | (z[2] + z[1]) >> 19);
				z[0] = z[0] ^ ((z[3] + z[2]) << 18 | (z[3] + z[2]) >> 14);

				z[6] = z[6] ^ ((z[5] + z[4]) << 7 | (z[5] + z[4]) >> 25);
				z[7] = z[7] ^ ((z[6] + z[5]) << 9 | (z[6] + z[5]) >> 23);
				z[4] = z[4] ^ ((z[7] + z[6]) << 13 | (z[7] + z[6]) >> 19);
				z[5] = z[5] ^ ((z[4] + z[7]) << 18 | (z[4] + z[7]) >> 14);

				z[11] = z[11] ^ ((z[10] + z[9]) << 7 | (z[10] + z[9]) >> 25);
				z[8] = z[8] ^ ((z[11] + z[10]) << 9 | (z[10] + z[11]) >> 23);
				z[9] = z[9] ^ ((z[8] + z[11]) << 13 | (z[8] + z[11]) >> 19);
				z[10] = z[10] ^ ((z[9] + z[8]) << 18 | (z[9] + z[8]) >> 14);

				z[12] = z[12] ^ ((z[15] + z[14]) << 7 | (z[15] + z[14]) >> 25);
				z[13] = z[13] ^ ((z[12] + z[15]) << 9 | (z[12] + z[15]) >> 23);
				z[14] = z[14] ^ ((z[13] + z[12]) << 13 | (z[13] + z[12]) >> 19);
				z[15] = z[15] ^ ((z[14] + z[13]) << 18 | (z[14] + z[13]) >> 14);
			}

			for (unsigned int j = 0; j < 16; ++j) {
				z[j] += x[j];
				keystream[(4 * j) + 0] = z[j];
				keystream[(4 * j) + 1] = z[j] >> 8;
				keystream[(4 * j) + 2] = z[j] >> 16;
				keystream[(4 * j) + 3] = z[j] >> 24;
			}
		}

		buf[i] ^= keystream[i % 64];
	}

	return;
}

void chacha20_encrypt
(
	unsigned char key[],
	unsigned char nonce[],
	unsigned char* bytes,
	unsigned long long n_bytes
)
{
	unsigned int keystream32[16];
	unsigned long long position;
	unsigned long long counter;
	unsigned int state[16];
	const unsigned char magic_constant[] = "expand 32-byte k";
	unsigned int res = 0;

	res |= (unsigned int)magic_constant[0] << 0 * 8;
	res |= (unsigned int)magic_constant[1] << 1 * 8;
	res |= (unsigned int)magic_constant[2] << 2 * 8;
	res |= (unsigned int)magic_constant[3] << 3 * 8;
	state[0] = res;

	res = 0;
	res |= (unsigned int)magic_constant[4] << 0 * 8;
	res |= (unsigned int)magic_constant[5] << 1 * 8;
	res |= (unsigned int)magic_constant[6] << 2 * 8;
	res |= (unsigned int)magic_constant[7] << 3 * 8;
	state[1] = res;

	res = 0;
	res |= (unsigned int)magic_constant[8] << 0 * 8;
	res |= (unsigned int)magic_constant[9] << 1 * 8;
	res |= (unsigned int)magic_constant[10] << 2 * 8;
	res |= (unsigned int)magic_constant[11] << 3 * 8;
	state[2] = res;

	res = 0;
	res |= (unsigned int)magic_constant[12] << 0 * 8;
	res |= (unsigned int)magic_constant[13] << 1 * 8;
	res |= (unsigned int)magic_constant[14] << 2 * 8;
	res |= (unsigned int)magic_constant[15] << 3 * 8;
	state[3] = res;

	res = 0;
	res |= (unsigned int)key[0] << 0 * 8;
	res |= (unsigned int)key[1] << 1 * 8;
	res |= (unsigned int)key[2] << 2 * 8;
	res |= (unsigned int)key[3] << 3 * 8;
	state[4] = res;

	res = 0;
	res |= (unsigned int)key[4] << 0 * 8;
	res |= (unsigned int)key[5] << 1 * 8;
	res |= (unsigned int)key[6] << 2 * 8;
	res |= (unsigned int)key[7] << 3 * 8;
	state[5] = res;

	res = 0;
	res |= (unsigned int)key[8] << 0 * 8;
	res |= (unsigned int)key[9] << 1 * 8;
	res |= (unsigned int)key[10] << 2 * 8;
	res |= (unsigned int)key[11] << 3 * 8;
	state[6] = res;

	res = 0;
	res |= (unsigned int)key[12] << 0 * 8;
	res |= (unsigned int)key[13] << 1 * 8;
	res |= (unsigned int)key[14] << 2 * 8;
	res |= (unsigned int)key[15] << 3 * 8;
	state[7] = res;

	res = 0;
	res |= (unsigned int)key[16] << 0 * 8;
	res |= (unsigned int)key[17] << 1 * 8;
	res |= (unsigned int)key[18] << 2 * 8;
	res |= (unsigned int)key[19] << 3 * 8;
	state[8] = res;

	res = 0;
	res |= (unsigned int)key[20] << 0 * 8;
	res |= (unsigned int)key[21] << 1 * 8;
	res |= (unsigned int)key[22] << 2 * 8;
	res |= (unsigned int)key[23] << 3 * 8;
	state[9] = res;

	res = 0;
	res |= (unsigned int)key[24] << 0 * 8;
	res |= (unsigned int)key[25] << 1 * 8;
	res |= (unsigned int)key[26] << 2 * 8;
	res |= (unsigned int)key[27] << 3 * 8;
	state[10] = res;

	res = 0;
	res |= (unsigned int)key[28] << 0 * 8;
	res |= (unsigned int)key[29] << 1 * 8;
	res |= (unsigned int)key[30] << 2 * 8;
	res |= (unsigned int)key[31] << 3 * 8;
	state[11] = res;

	state[12] = 0;
	res = 0;
	res |= (unsigned int)nonce[0] << 0 * 8;
	res |= (unsigned int)nonce[1] << 1 * 8;
	res |= (unsigned int)nonce[2] << 2 * 8;
	res |= (unsigned int)nonce[3] << 3 * 8;
	state[13] = res;

	res = 0;
	res |= (unsigned int)nonce[4] << 0 * 8;
	res |= (unsigned int)nonce[5] << 1 * 8;
	res |= (unsigned int)nonce[6] << 2 * 8;
	res |= (unsigned int)nonce[7] << 3 * 8;
	state[14] = res;

	res = 0;
	res |= (unsigned int)nonce[8] << 0 * 8;
	res |= (unsigned int)nonce[9] << 1 * 8;
	res |= (unsigned int)nonce[10] << 2 * 8;
	res |= (unsigned int)nonce[11] << 3 * 8;
	state[15] = res;

	counter = 0;
	position = 64;

	unsigned char* keystream8 = (unsigned char*)keystream32;
	for (unsigned long long i = 0; i < n_bytes; i++)
	{
		if (position >= 64)
		{
			for (unsigned int j = 0; j < 16; j++) {
				keystream32[j] = state[j];
			}

			for (unsigned int j = 0; j < 10; j++)
			{
				// (x << n) | (x >> (32 - n))
				keystream32[0] += keystream32[4];
				keystream32[12] = ((keystream32[12] ^ keystream32[0]) << 16) | ((keystream32[12] ^ keystream32[0]) >> 16);
				keystream32[8] += keystream32[12];
				keystream32[4] = ((keystream32[4] ^ keystream32[8]) << 12) | ((keystream32[4] ^ keystream32[8]) >> 20);
				keystream32[0] += keystream32[4];
				keystream32[12] = ((keystream32[12] ^ keystream32[0]) << 8) | ((keystream32[12] ^ keystream32[0]) >> 24);
				keystream32[8] += keystream32[12];
				keystream32[4] = ((keystream32[4] ^ keystream32[8]) << 7) | ((keystream32[4] ^ keystream32[8]) >> 25);

				keystream32[1] += keystream32[5];
				keystream32[13] = ((keystream32[13] ^ keystream32[1]) << 16) | ((keystream32[13] ^ keystream32[1]) >> 16);
				keystream32[9] += keystream32[13];
				keystream32[5] = ((keystream32[5] ^ keystream32[9]) << 12) | ((keystream32[5] ^ keystream32[9]) >> 20);
				keystream32[1] += keystream32[5];
				keystream32[13] = ((keystream32[13] ^ keystream32[1]) << 8) | ((keystream32[13] ^ keystream32[1]) >> 24);
				keystream32[9] += keystream32[13];
				keystream32[5] = ((keystream32[5] ^ keystream32[9]) << 7) | ((keystream32[5] ^ keystream32[9]) >> 25);

				keystream32[2] += keystream32[6];
				keystream32[14] = ((keystream32[14] ^ keystream32[2]) << 16) | ((keystream32[14] ^ keystream32[2]) >> 16);
				keystream32[10] += keystream32[14];
				keystream32[6] = ((keystream32[6] ^ keystream32[10]) << 12) | ((keystream32[6] ^ keystream32[10]) >> 20);
				keystream32[2] += keystream32[6];
				keystream32[14] = ((keystream32[14] ^ keystream32[2]) << 8) | ((keystream32[14] ^ keystream32[2]) >> 24);
				keystream32[10] += keystream32[14];
				keystream32[6] = ((keystream32[6] ^ keystream32[10]) << 7) | ((keystream32[6] ^ keystream32[10]) >> 25);

				keystream32[3] += keystream32[7];
				keystream32[15] = ((keystream32[15] ^ keystream32[3]) << 16) | ((keystream32[15] ^ keystream32[3]) >> 16);
				keystream32[11] += keystream32[15];
				keystream32[7] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);
				keystream32[3] += keystream32[7];
				keystream32[15] = ((keystream32[15] ^ keystream32[3]) << 8) | ((keystream32[15] ^ keystream32[3]) >> 24);
				keystream32[11] += keystream32[15];
				keystream32[7] = ((keystream32[7] ^ keystream32[11]) << 7) | ((keystream32[7] ^ keystream32[11]) >> 25);

				keystream32[0] += keystream32[5];
				keystream32[15] = ((keystream32[15] ^ keystream32[3]) << 16) | ((keystream32[15] ^ keystream32[3]) >> 16);
				keystream32[10] += keystream32[15];
				keystream32[5] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);
				keystream32[0] += keystream32[5];
				keystream32[15] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);
				keystream32[10] += keystream32[15];
				keystream32[5] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);

				keystream32[1] += keystream32[6];
				keystream32[12] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);
				keystream32[11] += keystream32[12];
				keystream32[6] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);
				keystream32[1] += keystream32[6];
				keystream32[12] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);
				keystream32[11] += keystream32[12];
				keystream32[6] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);

				keystream32[2] += keystream32[7];
				keystream32[13] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);
				keystream32[8] += keystream32[13];
				keystream32[7] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);
				keystream32[2] += keystream32[7];
				keystream32[13] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);
				keystream32[8] += keystream32[13];
				keystream32[7] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);

				keystream32[3] += keystream32[4];
				keystream32[14] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);
				keystream32[9] += keystream32[14];
				keystream32[4] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);
				keystream32[3] += keystream32[4];
				keystream32[14] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);
				keystream32[9] += keystream32[14];
				keystream32[4] = ((keystream32[7] ^ keystream32[11]) << 12) | ((keystream32[7] ^ keystream32[11]) >> 20);
			}

			for (unsigned int j = 0; j < 16; j++) {
				keystream32[j] += state[j];
			}

			unsigned int* counter = state + 12;
			counter[0]++;
			if (0 == counter[0]) {
				counter[1]++;
			}

			position = 0;
		}

		bytes[i] ^= keystream8[position];
		position++;
	}
}

void rc4_encrypt
(
	unsigned char* key,
	unsigned long long key_size,
	unsigned char* buffer,
	unsigned long long buffer_size
)
{
	unsigned char S[256];
	unsigned char temp = 0;
	unsigned int j = 0;

	for (unsigned int i = 0; i < 256; i++) {
		S[i] = i;
	}

	for (unsigned int i = 0; i < 256; i++) {
		j = (j + S[i] + key[i % key_size]) % 256;
		temp = S[i];
		S[i] = S[j];
		S[j] = temp;
	}

	unsigned int i = 0;
	j = 0;
	for (unsigned int n = 0; n < buffer_size; n++) {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;

		temp = S[i];
		S[i] = S[j];
		S[j] = temp;
		buffer[n] ^= S[(S[i] + S[j]) % 256];
	}
}

void xor_encrypt
(
	unsigned char* key,
	unsigned long long key_size,
	unsigned char* buffer,
	unsigned long long buffer_size
)
{
	for (unsigned int i = 0; i < buffer_size; i++) {
		buffer[i] ^= key[i % key_size];
	}
}

UINT32 _HashStringRotr32SubA
(
	UINT32 Value,
	UINT Count
)
{

	DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
	Count &= Mask;
	return (Value >> Count) | (Value << ((-Count) & Mask));
}

DWORD _HashStringRotr32A
(
	PCHAR String
)
{
	DWORD Value = 0;

	for (INT Index = 0; String[Index] != 0; Index++) {
		Value = String[Index] + _HashStringRotr32SubA(Value, SEED);
	}

	return Value;
}

VOID MemSet
(
	_In_ PBYTE pBuffer,
	_In_ BYTE Value,
	_In_ UINT64 uSize,
	_In_ BOOL DontKnow
)
{
	UINT64 i = 0;
	UINT64 uRemainder = 0;
	UINT64 uNewValue = 0;

	if (uSize < sizeof(UINT64)) {
		for (i = 0; i < uSize; i++) {
			pBuffer[i] = Value;
		}

		return;
	}
	else {
		uRemainder = uSize % sizeof(UINT64);
		uNewValue = Value * 0x101010101010101;
		for (i = 0; i < uSize / sizeof(UINT64); i++) {
			((PUINT64)pBuffer)[i] = uNewValue;
		}

		for (i = 0; i < uRemainder; i++) {
			pBuffer[(uSize - uRemainder) + i] = Value;
		}
	}
}

VOID MemCopy
(
	_In_ PBYTE pDest,
	_In_ PBYTE pSrc,
	_In_ UINT64 uSize,
	_In_ UINT8 DontKnow
)
{
	INT32 i = 0;
	UINT64 uRemainder = 0;
	PBYTE pNewSrc = NULL;
	UINT64 uTemp = 0;
	UINT64 uTempSize = 0;

	if (pDest == pSrc) {
		return;
	}

	if (pDest > pSrc && pDest < &pSrc[uSize]) {
		uTemp = (UINT64)pDest - (UINT64)pSrc;
		uTempSize = uSize - uTemp;
		uRemainder = uTempSize % sizeof(UINT64);
		for (i = 0; i < uTempSize / sizeof(UINT64); i++) {
			((PUINT64)&pSrc[uSize + uTemp])[-1 - i] = ((PUINT64)&pSrc[uSize])[-1 - i];
		}

		if (uRemainder > 0) {
			for (i = uRemainder - 1; i >= 0; i--) {
				pDest[uTemp + i] = pDest[i];
			}
		}
		
		MemCopy(pDest, pSrc, uTemp, DontKnow);
	}
	else {
		uRemainder = uSize % sizeof(UINT64);
		for (i = 0; i < uSize / sizeof(UINT64); i++) {
			((PUINT64)pDest)[i] = ((PUINT64)pSrc)[i];
		}

		for (i = 0; i < uRemainder; i++) {
			pDest[(uSize - uRemainder) + i] = pSrc[(uSize - uRemainder) + i];
		}
	}
}

INT32 MemCmp
(
	_In_ PBYTE pBuffer1,
	_In_ PBYTE pBuffer2,
	_In_ UINT64 uSize
)
{
	DWORD i = 0;

	for (i = 0; i < uSize; i++) {
		if (pBuffer1[i] != pBuffer2[i]) {
			return 1;
		}
	}

	return 0;
}

FARPROC GetProcAddressH
(
	DWORD dwModuleHash,
	DWORD dwApiHash
)
{
	HMODULE hModule = NULL;
	PIMAGE_DOS_HEADER pDosHdr = NULL;
	PIMAGE_NT_HEADERS64 pNtHdr = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
	DWORD i = 0;
	DWORD j = 0;
	PDWORD pAddressTable = NULL;
	PDWORD pNameTable = NULL;
	PWORD pNameOrdTable = NULL;
	UINT64 DllBaseAddress = 0;
	LPSTR lpFunctionName = NULL;
	PIMAGE_SECTION_HEADER pTextSection = NULL;
	DWORD dwNumberOfSections = 0;
	DWORD dwFunctionRVA = 0;
	UINT64 uResult = 0x1122334455667788;
	CHAR szDllName[0x40];
	LPSTR lpProcInfo = NULL;
	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
	WCHAR Temp = L'\0';
	PBYTE pFunctionPointer = NULL;
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPSTR);
typedef FARPROC(WINAPI* LOADLIBRARYA)(LPSTR);
	GETPROCADDRESS fnGetProcAddress = NULL;
	LOADLIBRARYA fnLoadLibraryA = NULL;
	DWORD dwKernelBaseHash = 0;
	DWORD dwGetProcAddressHash = 0;
	DWORD dwLoadLibraryAHash = 0;

	if (dwModuleHash == dwApiHash) {
		uResult = 0;
	}

	dwGetProcAddressHash = HASHA("GetProcAddress");
	dwLoadLibraryAHash = HASHA("LoadLibraryA");
	if (dwApiHash != dwGetProcAddressHash && dwApiHash != dwLoadLibraryAHash && uResult != 0x1122334455667788) {
		return (FARPROC)uResult;
	}
	else {
		uResult = 0;
	}

	while (pDte) {
		if (pDte->FullDllName.Buffer != NULL) {
			if (pDte->FullDllName.Length < MAX_PATH - 1) {
				i = 0;
				while (pDte->FullDllName.Buffer[i] != L'\0') {
					Temp = pDte->FullDllName.Buffer[i];
					if (Temp >= L'a' && Temp <= L'z') {
						szDllName[i] = (CHAR)(Temp - L'a' + L'A');
					}
					else {
						szDllName[i] = (CHAR)Temp;
					}

					i++;
				}

				szDllName[i] = '\0';
				if (HASHA(szDllName) == dwModuleHash) {
					hModule = (HMODULE)(pDte->InInitializationOrderLinks.Flink);
					break;
				}
			}
		}
		else {
			break;
		}

		pDte = (PLDR_DATA_TABLE_ENTRY)(*(PUINT64)(pDte));
	}

	if (hModule == NULL) {
		return NULL;
	}

	DllBaseAddress = (UINT64)hModule;
	pNtHdr = (PIMAGE_NT_HEADERS64)(DllBaseAddress + ((PIMAGE_DOS_HEADER)DllBaseAddress)->e_lfanew);
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)(DllBaseAddress + pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	pAddressTable = (PDWORD)(DllBaseAddress + pExportDir->AddressOfFunctions);
	pNameOrdTable = (PWORD)(DllBaseAddress + pExportDir->AddressOfNameOrdinals);
	pNameTable = (PDWORD)(DllBaseAddress + pExportDir->AddressOfNames);
	pTextSection = (PIMAGE_SECTION_HEADER)((UINT64)(&pNtHdr->OptionalHeader) + pNtHdr->FileHeader.SizeOfOptionalHeader);
	dwNumberOfSections = pNtHdr->FileHeader.NumberOfSections;
	for (i = 0; i < dwNumberOfSections; i++) {
		pTextSection += i;
		if (pTextSection->Name[0] == '.' && pTextSection->Name[1] == 't' && pTextSection->Name[2] == 'e' && pTextSection->Name[3] == 'x' && pTextSection->Name[4] == 't' && pTextSection->Name[5] == '\0') {
			break;
		}
	}

	for (i = 0; i < pExportDir->NumberOfNames; i++) {
		lpFunctionName = (LPSTR)(DllBaseAddress + pNameTable[i]);
		if (HASHA(lpFunctionName) == dwApiHash) {
			dwFunctionRVA = pAddressTable[pNameOrdTable[i]];
			if (dwFunctionRVA >= pTextSection->VirtualAddress && dwFunctionRVA < pTextSection->VirtualAddress + pTextSection->Misc.VirtualSize) {
				uResult = DllBaseAddress + dwFunctionRVA;
			}
			else {
				lpProcInfo = (LPSTR)(DllBaseAddress + dwFunctionRVA);
				while (lpProcInfo[j] != '\0') {
					if (lpProcInfo[j] == '.') {
						break;
					}

					j++;
				}

				if (lpProcInfo[j] == '.') {
					lpFunctionName = &lpProcInfo[j + 1];
					memcpy(szDllName, lpProcInfo, j);
					szDllName[j] = '.';
					szDllName[j + 1] = 'D';
					szDllName[j + 2] = 'L';
					szDllName[j + 3] = 'L';
					szDllName[j + 4] = '\0';
					dwKernelBaseHash = HASHA("KERNELBASE.DLL");
					fnGetProcAddress = (GETPROCADDRESS)GetProcAddressH(dwKernelBaseHash, dwGetProcAddressHash);
					fnLoadLibraryA = (LOADLIBRARYA)GetProcAddressH(dwKernelBaseHash, dwLoadLibraryAHash);
					hModule = fnLoadLibraryA(szDllName);
					uResult = (UINT64)fnGetProcAddress(hModule, lpFunctionName);
					break;
				}
			}

			break;
		}
	}

	if (dwApiHash != dwGetProcAddressHash && dwApiHash != dwLoadLibraryAHash && uResult != 0) {
		pFunctionPointer = (PUINT64)GetProcAddressH;
		i = 0;
		while (TRUE) {
			if (*((PUINT64)(&pFunctionPointer[i])) == 0x1122334455667788) {
				*((PUINT64)(&pFunctionPointer[i])) = uResult;
				break;
			}

			i++;
		}
	}

	return (FARPROC)uResult;
}