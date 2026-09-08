/* Host integration test: decrypt a generated OTA with the Bootloader C core. */
#include "ota_aes_gcm.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HEADER_SIZE 148U
#define SIGNATURE_SIZE 3309U
#define NONCE_OFFSET 116U
#define TAG_OFFSET 128U
#define CRC_OFFSET 144U

static unsigned char *read_all(const char *path, size_t *length)
{
    FILE *f = fopen(path, "rb");
    unsigned char *p;
    long n;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); n = ftell(f); rewind(f);
    if (n < 0) { fclose(f); return NULL; }
    p = (unsigned char *)malloc((size_t)n);
    if (!p || fread(p, 1U, (size_t)n, f) != (size_t)n) {
        free(p); fclose(f); return NULL;
    }
    fclose(f); *length = (size_t)n; return p;
}

int main(int argc, char **argv)
{
    unsigned char *ota, *app, *key, *cipher, aad[HEADER_SIZE];
    size_t ota_len, app_len, key_len, cipher_len;
    ota_aes_gcm_ctx_t ctx;
    if (argc != 4) return 1;
    ota = read_all(argv[1], &ota_len); key = read_all(argv[2], &key_len);
    app = read_all(argv[3], &app_len);
    if (!ota || !key || !app || key_len != 32U ||
        ota_len < HEADER_SIZE + SIGNATURE_SIZE) return 2;
    cipher_len = ota_len - HEADER_SIZE - SIGNATURE_SIZE;
    if (cipher_len != app_len) return 3;
    cipher = &ota[HEADER_SIZE + SIGNATURE_SIZE];
    memcpy(aad, ota, HEADER_SIZE);
    memset(&aad[TAG_OFFSET], 0, 16U); memset(&aad[CRC_OFFSET], 0, 4U);
    if (!ota_aes_gcm_decrypt_init(&ctx, key, &ota[NONCE_OFFSET], aad, sizeof(aad))) return 4;
    /* Deliberately split across non-block-aligned boundaries. */
    ota_aes_gcm_decrypt_update(&ctx, cipher, cipher, 13U);
    ota_aes_gcm_decrypt_update(&ctx, cipher + 13U, cipher + 13U,
                               cipher_len - 13U);
    if (!ota_aes_gcm_decrypt_final(&ctx, &ota[TAG_OFFSET])) return 5;
    if (memcmp(cipher, app, app_len) != 0) return 6;
    puts("[C AES-GCM] PASS: generated OTA decrypted byte-identically");
    free(ota); free(key); free(app);
    return 0;
}
