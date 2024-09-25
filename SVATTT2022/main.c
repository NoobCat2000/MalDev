#include "pch.h"

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
#define QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);
#define U32TO8_LITTLE(p, v) (((UINT32*)(p))[0] = U32TO32_LITTLE(v))
#define AGE_FILEKEY_SIZE (16)
#define STREAM_NONCE_SIZE (16)
#define ALLOC(X) RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, X)
#define FREE(X) RtlFreeHeap(GetProcessHeap(), 0, X)
#define REALLOC(X, Y) RtlReAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, X, Y)

typedef struct _POLY1305_CTX {
	UINT32 h[5];
	UINT32 r[4];
	UINT32 Nonce[4];
	DWORD dwNum;
	BYTE Data[POLY1305_BLOCK_SIZE];
} POLY1305_CTX, * PPOLY1305_CTX;

typedef struct _CHACHA20POLY1305_CONTEXT
{
	POLY1305_CTX PolyCtx;
	UINT32 Input[16];
} CHACHA20POLY1305_CONTEXT, * PCHACHA20POLY1305_CONTEXT;

#include "pch.h"

#define DEREF( name )		*(	UINT_PTR	*)	(name)
#define DEREF_64( name )	*(	DWORD64		*)	(name)
#define DEREF_32( name )	*(	DWORD		*)	(name)
#define DEREF_16( name )	*(	WORD		*)	(name)
#define DEREF_8( name )		*(	BYTE		*)	(name)
#define HASHA(API)		    (_HashStringRotr32A((PCHAR) API))
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
	unsigned char t[4][4] = {
	  { 'e', 'x', 'p', 'a' },
	  { 'n', 'd', ' ', '1' },
	  { '6', '-', 'b', 'y' },
	  { 't', 'e', ' ', 'k' }
	};

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
					keystream[z + j] = t[z / 20][j];
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
	const unsigned char magic_constant[] = { 'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k', '\0' };
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

CHAR _ToUpper
(
	CHAR c
)
{

	if (c >= 'a' && c <= 'z') {
		return c - 'a' + 'A';
	}

	return c;
}

HMODULE GetModuleHandleH
(
	DWORD ModuleHash
)
{
	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {
		if (pDte->FullDllName.Buffer != NULL) {
			if (pDte->FullDllName.Length < MAX_PATH - 1) {
				CHAR DllName[MAX_PATH] = { 0 };
				DWORD i = 0;
				while (pDte->FullDllName.Buffer[i] && i < sizeof(DllName) - 1) {
					DllName[i] = _ToUpper((char)pDte->FullDllName.Buffer[i]);
					i++;
				}
				DllName[i] = '\0';
				if (HASHA(DllName) == ModuleHash) {
					return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
				}
			}
		}
		else {
			break;
		}

		pDte = (PLDR_DATA_TABLE_ENTRY)DEREF_64(pDte);
	}
	return NULL;
}

FARPROC GetProcAddressH
(
	DWORD moduleHash,
	DWORD Hash
)
{
	HMODULE hModule = GetModuleHandleH(moduleHash);
	if (hModule == NULL || Hash == 0)
		return NULL;

	HMODULE hModule2 = NULL;
	UINT64	DllBaseAddress = (UINT64)hModule;

	PIMAGE_NT_HEADERS NtHdr = (PIMAGE_NT_HEADERS)(DllBaseAddress + ((PIMAGE_DOS_HEADER)DllBaseAddress)->e_lfanew);
	PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)&NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY ExportTable = (PIMAGE_EXPORT_DIRECTORY)(DllBaseAddress + pDataDir->VirtualAddress);

	UINT64 FunctionNameAddressArray = (DllBaseAddress + ExportTable->AddressOfNames);
	UINT64 FunctionAddressArray = (DllBaseAddress + ExportTable->AddressOfFunctions);
	UINT64 FunctionOrdinalAddressArray = (DllBaseAddress + ExportTable->AddressOfNameOrdinals);
	UINT64 pFunctionAddress = 0;

	DWORD	dwCounter = ExportTable->NumberOfNames;
	while (dwCounter--) {
		char* FunctionName = (char*)(DllBaseAddress + DEREF_32(FunctionNameAddressArray));

		if (HASHA(FunctionName) == Hash) {
			FunctionAddressArray += (DEREF_16(FunctionOrdinalAddressArray) * sizeof(DWORD));
			pFunctionAddress = (UINT64)(DllBaseAddress + DEREF_32(FunctionAddressArray));

			// if (pDataDir->VirtualAddress <= DEREF_32(FunctionAddressArray) && (pDataDir->VirtualAddress + pDataDir->Size) >= DEREF_32(FunctionAddressArray)) {
			// 	CHAR Library[MAX_PATH] = { 0 };
			// 	CHAR Function[MAX_PATH] = { 0 };
			// 	UINT32 Index = _CopyDotStr((PCHAR)pFunctionAddress);
			// 	if (Index == 0) {
			// 		return NULL;
			// 	}

			// 	memcpy((PVOID)Library, (PVOID)pFunctionAddress, Index);
			// 	memcpy((PVOID)Function, (PVOID)((ULONG_PTR)pFunctionAddress + Index + 1), lstrlenA((LPSTR)((ULONG_PTR)pFunctionAddress + Index + 1)));
			// 	pFunctionAddress = (UINT64)GetProcAddressH(HASHA(Library), HASHA(Function));
			// }
			break;
		}
		FunctionNameAddressArray += sizeof(DWORD);
		FunctionOrdinalAddressArray += sizeof(WORD);
	}
	return (FARPROC)pFunctionAddress;
}

VOID U32TO8
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

PBYTE GenRandomBytes
(
	_In_ DWORD dwSize
)
{
	LPSTR lpResult = NULL;
	HMODULE hAdvapi32 = NULL;
	typedef BOOLEAN(WINAPI* SYSTEMFUNCTION036)(PVOID, ULONG);
	SYSTEMFUNCTION036 pRtlGenRandom = NULL;

	hAdvapi32 = LoadLibraryW(L"Advapi32.dll");
	pRtlGenRandom = (SYSTEMFUNCTION036)GetProcAddress(hAdvapi32, "SystemFunction036");
	lpResult = ALLOC(dwSize + 1);
	pRtlGenRandom(lpResult, dwSize);

	return lpResult;
}

UINT32 U8TOU32
(
	PBYTE p
)
{
	return (((UINT32)(p[0] & 0xff)) |
		((UINT32)(p[1] & 0xff) << 8) |
		((UINT32)(p[2] & 0xff) << 16) |
		((UINT32)(p[3] & 0xff) << 24));
}

LPWSTR DuplicateStrW
(
	_In_ LPWSTR lpInput,
	_In_ DWORD dwAdditionalLength
)
{
	LPWSTR lpResult = NULL;
	DWORD cbInput = 0;

	if (lpInput == NULL) {
		return ALLOC(sizeof(WCHAR));
	}

	cbInput = lstrlenW(lpInput);
	if (dwAdditionalLength == 0)
	{
		lpResult = ALLOC((cbInput + 1) * sizeof(WCHAR));
	}
	else {
		lpResult = ALLOC((cbInput + dwAdditionalLength + 1) * sizeof(WCHAR));
	}

	lstrcpyW(lpResult, lpInput);
	return lpResult;
}

VOID Chacha20Encrypt
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
	INT32 i;

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
		h0 = (UINT32)(d0 = (UINT64)h0 + U8TOU32(pBuffer + 0));
		h1 = (UINT32)(d1 = (UINT64)h1 + (d0 >> 32) + U8TOU32(pBuffer + 4));
		h2 = (UINT32)(d2 = (UINT64)h2 + (d1 >> 32) + U8TOU32(pBuffer + 8));
		h3 = (UINT32)(d3 = (UINT64)h3 + (d2 >> 32) + U8TOU32(pBuffer + 12));
		h4 += (UINT32)(d3 >> 32) + dwPadBit;

		d0 = ((UINT64)h0 * r0) + ((UINT64)h1 * s3) + ((UINT64)h2 * s2) + ((UINT64)h3 * s1);
		d1 = ((UINT64)h0 * r1) + ((UINT64)h1 * r0) + ((UINT64)h2 * s3) + ((UINT64)h3 * s2) + (h4 * s1);
		d2 = ((UINT64)h0 * r2) + ((UINT64)h1 * r1) + ((UINT64)h2 * r0) + ((UINT64)h3 * s3) + (h4 * s2);
		d3 = ((UINT64)h0 * r3) + ((UINT64)h1 * r2) + ((UINT64)h2 * r1) + ((UINT64)h3 * r0) + (h4 * s3);
		h4 = (h4 * r0);

		h0 = (UINT32)d0;
		h1 = (UINT32)(d1 += d0 >> 32);
		h2 = (UINT32)(d2 += d1 >> 32);
		h3 = (UINT32)(d3 += d2 >> 32);
		h4 += (UINT32)(d3 >> 32);
		c = (h4 >> 2) + (h4 & ~3U);
		h4 &= 3;
		h0 += c;
		h1 += (c = CONSTANT_TIME_CARRY(h0, c));
		h2 += (c = CONSTANT_TIME_CARRY(h1, c));
		h3 += (c = CONSTANT_TIME_CARRY(h2, c));
		h4 += CONSTANT_TIME_CARRY(h3, c);
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
	DWORD cbPaddedAAD = (cbAAD % POLY1305_BLOCK_SIZE) == 0 ? cbAAD : cbAAD - (cbAAD % POLY1305_BLOCK_SIZE) + POLY1305_BLOCK_SIZE;
	DWORD cbPaddeMsg = (cbMessage % POLY1305_BLOCK_SIZE) == 0 ? cbMessage : cbMessage - (cbMessage % POLY1305_BLOCK_SIZE) + POLY1305_BLOCK_SIZE;

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

int main() {
	PBYTE pKey = NULL;
	PBYTE pNonce = NULL;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	LPWSTR lpCommandLine = NULL;
	DWORD dwNumArgs = 0;
	LPWSTR* lpArgs = NULL;
	LPWSTR lpNewFileName = NULL;
	DWORD dwFileSize = 0;
	PBYTE pBuffer = NULL;
	DWORD dwNumberOfBytesRead = 0;
	DWORD dwNumberOfBytesWritten = 0;
	PBYTE pCipherText = NULL;
	DWORD cbCipherText = 0;
	HANDLE hEncryptedFile = INVALID_HANDLE_VALUE;
	DWORD i = 0;

	LoadLibraryW(L"shell32.dll");
	lpCommandLine = GetCommandLineW();
	lpArgs = CommandLineToArgvW(lpCommandLine, &dwNumArgs);
	if (dwNumArgs == 1) {
		LogError(L"argc <= 1. Run again with the file you want to encrypt.");
	}
	
	hFile = CreateFileW(lpArgs[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		goto CLEANUP;
	}

	dwFileSize = GetFileSize(hFile, NULL);
	pBuffer = ALLOC(dwFileSize + CHACHA20_KEY_SIZE + CHACHA20_NONCE_SIZE);
	if (!ReadFile(hFile, pBuffer, dwFileSize, &dwNumberOfBytesRead, NULL)) {
		goto CLEANUP;
	}

	pKey = GenRandomBytes(CHACHA20_KEY_SIZE);
	pNonce = GenRandomBytes(CHACHA20_NONCE_SIZE);
	Chacha20Poly1305Encrypt(pKey, pNonce, pBuffer, dwFileSize, NULL, 0, &pCipherText, &cbCipherText);
	for (i = 0; i < CHACHA20_KEY_SIZE; i++) {
		pKey[i] ^= pNonce[i % CHACHA20_NONCE_SIZE];
		pKey[i] ^= 0xE1;
	}

	pCipherText = REALLOC(pCipherText, cbCipherText + CHACHA20_KEY_SIZE + CHACHA20_NONCE_SIZE);
	memcpy(&pCipherText[cbCipherText], pKey, CHACHA20_KEY_SIZE);
	memcpy(&pCipherText[cbCipherText + CHACHA20_KEY_SIZE], pNonce, CHACHA20_NONCE_SIZE);
	lpNewFileName = DuplicateStrW(lpArgs[1], 7);
	lstrcatW(lpNewFileName, L".svattt");
	hEncryptedFile = CreateFileW(lpNewFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hEncryptedFile == INVALID_HANDLE_VALUE) {
		goto CLEANUP;
	}

	if (!WriteFile(hEncryptedFile, pCipherText, cbCipherText + CHACHA20_KEY_SIZE + CHACHA20_NONCE_SIZE, &dwNumberOfBytesWritten, NULL)) {
		goto CLEANUP;
	}

CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}

	if (hEncryptedFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hEncryptedFile);
	}

	if (pBuffer != NULL) {
		FREE(pBuffer);
	}

	if (pKey != NULL) {
		FREE(pKey);
	}

	if (pNonce != NULL) {
		FREE(pNonce);
	}

	if (pCipherText != NULL) {
		FREE(pCipherText);
	}
	
	if (lpNewFileName != NULL) {
		FREE(lpNewFileName);
	}

	return 0;
}