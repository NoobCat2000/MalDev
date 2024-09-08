#pragma once

static void salsa20_encrypt
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

static void chacha20_encrypt(unsigned char key[], unsigned char nonce[], unsigned char* bytes, unsigned long long n_bytes)
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

    memcpy(nonce, nonce, sizeof(nonce));
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

static void rc4_encrypt
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

static void xor_encrypt
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

#include "framework.h"

#include "Communication.h"
#include <Utils.h>
