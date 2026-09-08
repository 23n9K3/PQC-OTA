#ifndef OTA_AES_GCM_H
#define OTA_AES_GCM_H

#include <stddef.h>
#include <stdint.h>

#define OTA_AES256_KEY_SIZE 32U
#define OTA_AES_BLOCK_SIZE 16U
#define OTA_AES_GCM_NONCE_SIZE 12U
#define OTA_AES_GCM_TAG_SIZE 16U

typedef struct {
    uint8_t round_key[240];
    uint8_t hash_subkey[16];
    uint8_t ghash[16];
    uint8_t j0[16];
    uint8_t counter[16];
    uint8_t stream[16];
    uint8_t ghash_buffer[16];
    uint32_t stream_used;
    uint32_t ghash_buffer_len;
    uint64_t aad_length;
    uint64_t ciphertext_length;
} ota_aes_gcm_ctx_t;

/* Streaming AES-256-GCM authenticated decryption for a 96-bit nonce. */
int ota_aes_gcm_decrypt_init(ota_aes_gcm_ctx_t *ctx,
                             const uint8_t key[OTA_AES256_KEY_SIZE],
                             const uint8_t nonce[OTA_AES_GCM_NONCE_SIZE],
                             const uint8_t *aad, size_t aad_length);
void ota_aes_gcm_decrypt_update(ota_aes_gcm_ctx_t *ctx,
                                const uint8_t *ciphertext,
                                uint8_t *plaintext, size_t length);
int ota_aes_gcm_decrypt_final(ota_aes_gcm_ctx_t *ctx,
                              const uint8_t expected_tag[OTA_AES_GCM_TAG_SIZE]);

#endif
