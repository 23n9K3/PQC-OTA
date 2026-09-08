#ifndef OTA_CRYPTO_H
#define OTA_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#define OTA_SHA256_SIZE 32U

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t buffer[64];
    uint32_t buffer_len;
} ota_sha256_ctx_t;

/* SHA-256 用于最小 OTA 阶段的固件完整性校验。 */
void ota_sha256_init(ota_sha256_ctx_t *ctx);
void ota_sha256_update(ota_sha256_ctx_t *ctx, const uint8_t *data, size_t length);
void ota_sha256_final(ota_sha256_ctx_t *ctx, uint8_t hash[OTA_SHA256_SIZE]);
void ota_sha256_compute(const uint8_t *data, size_t length, uint8_t hash[OTA_SHA256_SIZE]);
int ota_hash_equal(const uint8_t a[OTA_SHA256_SIZE], const uint8_t b[OTA_SHA256_SIZE]);

#endif
