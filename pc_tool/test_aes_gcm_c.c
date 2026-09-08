/* Host known-answer test for the exact AES-256-GCM core used by Bootloader. */
#include "ota_aes_gcm.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    static const unsigned char key[32] = {0};
    static const unsigned char nonce[12] = {0};
    static const unsigned char ciphertext[16] = {
        0xce,0xa7,0x40,0x3d,0x4d,0x60,0x6b,0x6e,
        0x07,0x4e,0xc5,0xd3,0xba,0xf3,0x9d,0x18
    };
    static const unsigned char tag[16] = {
        0xd0,0xd1,0xc8,0xa7,0x99,0x99,0x6b,0xf0,
        0x26,0x5b,0x98,0xb5,0xd4,0x8a,0xb9,0x19
    };
    ota_aes_gcm_ctx_t ctx;
    unsigned char plaintext[16];
    unsigned char expected[16] = {0};

    if (!ota_aes_gcm_decrypt_init(&ctx, key, nonce, NULL, 0U)) return 1;
    ota_aes_gcm_decrypt_update(&ctx, ciphertext, plaintext, 7U);
    ota_aes_gcm_decrypt_update(&ctx, ciphertext + 7U, plaintext + 7U, 9U);
    if (!ota_aes_gcm_decrypt_final(&ctx, tag)) return 2;
    if (memcmp(plaintext, expected, sizeof(expected)) != 0) return 3;
    puts("[C AES-GCM] PASS: AES-256-GCM NIST vector and split streaming");
    return 0;
}
