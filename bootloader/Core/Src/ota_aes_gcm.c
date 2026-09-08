#include "ota_aes_gcm.h"

#include <string.h>

/* Compact AES-256 encrypt-only core plus GCM GHASH. */
static const uint8_t sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1U) ^ (((x >> 7U) & 1U) * 0x1bU));
}

static void key_expansion(uint8_t round_key[240], const uint8_t key[32])
{
    uint32_t bytes = 32U;
    uint8_t rcon = 1U;
    uint8_t t[4];
    memcpy(round_key, key, 32U);
    while (bytes < 240U) {
        for (uint32_t i = 0U; i < 4U; i++) t[i] = round_key[bytes - 4U + i];
        if ((bytes % 32U) == 0U) {
            uint8_t q = t[0];
            t[0] = (uint8_t)(sbox[t[1]] ^ rcon);
            t[1] = sbox[t[2]]; t[2] = sbox[t[3]]; t[3] = sbox[q];
            rcon = xtime(rcon);
        } else if ((bytes % 32U) == 16U) {
            for (uint32_t i = 0U; i < 4U; i++) t[i] = sbox[t[i]];
        }
        for (uint32_t i = 0U; i < 4U; i++) {
            round_key[bytes] = (uint8_t)(round_key[bytes - 32U] ^ t[i]);
            bytes++;
        }
    }
}

static void add_round_key(uint8_t s[16], const uint8_t *rk)
{
    for (uint32_t i = 0U; i < 16U; i++) s[i] ^= rk[i];
}

static void shift_rows(uint8_t s[16])
{
    uint8_t t;
    t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[3]; s[3]=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=t;
}

static void mix_columns(uint8_t s[16])
{
    for (uint32_t c = 0U; c < 4U; c++) {
        uint8_t *a = &s[c * 4U];
        uint8_t x = (uint8_t)(a[0] ^ a[1] ^ a[2] ^ a[3]);
        uint8_t a0 = a[0];
        a[0] ^= (uint8_t)(x ^ xtime((uint8_t)(a[0] ^ a[1])));
        a[1] ^= (uint8_t)(x ^ xtime((uint8_t)(a[1] ^ a[2])));
        a[2] ^= (uint8_t)(x ^ xtime((uint8_t)(a[2] ^ a[3])));
        a[3] ^= (uint8_t)(x ^ xtime((uint8_t)(a[3] ^ a0)));
    }
}

static void aes256_encrypt_block(const uint8_t round_key[240],
                                 const uint8_t input[16], uint8_t output[16])
{
    uint8_t s[16];
    memcpy(s, input, 16U);
    add_round_key(s, round_key);
    for (uint32_t round = 1U; round < 14U; round++) {
        for (uint32_t i = 0U; i < 16U; i++) s[i] = sbox[s[i]];
        shift_rows(s); mix_columns(s);
        add_round_key(s, &round_key[round * 16U]);
    }
    for (uint32_t i = 0U; i < 16U; i++) s[i] = sbox[s[i]];
    shift_rows(s);
    add_round_key(s, &round_key[224]);
    memcpy(output, s, 16U);
    memset(s, 0, sizeof(s));
}

static void xor_block(uint8_t a[16], const uint8_t b[16])
{
    for (uint32_t i = 0U; i < 16U; i++) a[i] ^= b[i];
}

static void right_shift_one(uint8_t v[16])
{
    uint8_t carry = 0U;
    for (uint32_t i = 0U; i < 16U; i++) {
        uint8_t next = (uint8_t)(v[i] & 1U);
        v[i] = (uint8_t)((v[i] >> 1U) | (carry << 7U));
        carry = next;
    }
}

static void ghash_multiply(uint8_t x[16], const uint8_t h[16])
{
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, h, 16U);
    for (uint32_t i = 0U; i < 128U; i++) {
        if ((x[i >> 3U] & (uint8_t)(0x80U >> (i & 7U))) != 0U) xor_block(z, v);
        {
            uint8_t lsb = (uint8_t)(v[15] & 1U);
            right_shift_one(v);
            if (lsb != 0U) v[0] ^= 0xe1U;
        }
    }
    memcpy(x, z, 16U);
}

static void ghash_block(ota_aes_gcm_ctx_t *ctx, const uint8_t block[16])
{
    xor_block(ctx->ghash, block);
    ghash_multiply(ctx->ghash, ctx->hash_subkey);
}

static void ghash_bytes(ota_aes_gcm_ctx_t *ctx, const uint8_t *data, size_t length)
{
    while (length > 0U) {
        uint32_t take = 16U - ctx->ghash_buffer_len;
        if (take > length) take = (uint32_t)length;
        memcpy(&ctx->ghash_buffer[ctx->ghash_buffer_len], data, take);
        ctx->ghash_buffer_len += take;
        data += take; length -= take;
        if (ctx->ghash_buffer_len == 16U) {
            ghash_block(ctx, ctx->ghash_buffer);
            ctx->ghash_buffer_len = 0U;
        }
    }
}

static void ghash_pad(ota_aes_gcm_ctx_t *ctx)
{
    if (ctx->ghash_buffer_len != 0U) {
        memset(&ctx->ghash_buffer[ctx->ghash_buffer_len], 0,
               16U - ctx->ghash_buffer_len);
        ghash_block(ctx, ctx->ghash_buffer);
        ctx->ghash_buffer_len = 0U;
    }
}

static void increment_counter(uint8_t counter[16])
{
    for (uint32_t i = 16U; i > 12U; i--) {
        counter[i - 1U]++;
        if (counter[i - 1U] != 0U) break;
    }
}

static void store_be64(uint8_t out[8], uint64_t value)
{
    for (uint32_t i = 0U; i < 8U; i++) out[7U - i] = (uint8_t)(value >> (i * 8U));
}

int ota_aes_gcm_decrypt_init(ota_aes_gcm_ctx_t *ctx, const uint8_t key[32],
                             const uint8_t nonce[12], const uint8_t *aad,
                             size_t aad_length)
{
    uint8_t zero[16] = {0};
    if ((ctx == NULL) || (key == NULL) || (nonce == NULL) ||
        ((aad == NULL) && (aad_length != 0U))) return 0;
    memset(ctx, 0, sizeof(*ctx));
    key_expansion(ctx->round_key, key);
    aes256_encrypt_block(ctx->round_key, zero, ctx->hash_subkey);
    memcpy(ctx->j0, nonce, 12U);
    ctx->j0[15] = 1U;
    memcpy(ctx->counter, ctx->j0, 16U);
    increment_counter(ctx->counter);
    ctx->stream_used = 16U;
    ctx->aad_length = aad_length;
    ghash_bytes(ctx, aad, aad_length);
    ghash_pad(ctx);
    return 1;
}

void ota_aes_gcm_decrypt_update(ota_aes_gcm_ctx_t *ctx, const uint8_t *ciphertext,
                                uint8_t *plaintext, size_t length)
{
    if ((ctx == NULL) || (ciphertext == NULL) || (plaintext == NULL)) return;
    ghash_bytes(ctx, ciphertext, length);
    ctx->ciphertext_length += length;
    for (size_t i = 0U; i < length; i++) {
        if (ctx->stream_used == 16U) {
            aes256_encrypt_block(ctx->round_key, ctx->counter, ctx->stream);
            increment_counter(ctx->counter);
            ctx->stream_used = 0U;
        }
        plaintext[i] = (uint8_t)(ciphertext[i] ^ ctx->stream[ctx->stream_used++]);
    }
}

int ota_aes_gcm_decrypt_final(ota_aes_gcm_ctx_t *ctx, const uint8_t expected_tag[16])
{
    uint8_t length_block[16];
    uint8_t tag[16];
    uint8_t diff = 0U;
    if ((ctx == NULL) || (expected_tag == NULL)) return 0;
    ghash_pad(ctx);
    store_be64(&length_block[0], ctx->aad_length * 8ULL);
    store_be64(&length_block[8], ctx->ciphertext_length * 8ULL);
    ghash_block(ctx, length_block);
    aes256_encrypt_block(ctx->round_key, ctx->j0, tag);
    xor_block(tag, ctx->ghash);
    for (uint32_t i = 0U; i < 16U; i++) diff |= (uint8_t)(tag[i] ^ expected_tag[i]);
    memset(ctx, 0, sizeof(*ctx));
    memset(tag, 0, sizeof(tag));
    return diff == 0U;
}
