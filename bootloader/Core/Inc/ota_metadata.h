#ifndef OTA_METADATA_H
#define OTA_METADATA_H

#include <stdint.h>
#include "ota_crypto.h"

typedef struct {
    uint32_t magic;
    uint32_t active_slot;
    uint32_t app_a_valid;
    uint32_t app_b_valid;
    uint32_t pending_verify;
    uint32_t boot_count;
    uint32_t app_a_size;
    uint32_t app_b_size;
    uint8_t app_a_hash[OTA_SHA256_SIZE];
    uint8_t app_b_hash[OTA_SHA256_SIZE];
    uint32_t crc32;
} ota_metadata_t;

void ota_metadata_load_or_init(ota_metadata_t *meta);
int ota_metadata_save(ota_metadata_t *meta);
void ota_metadata_prepare_app_b(ota_metadata_t *meta, uint32_t size, const uint8_t hash[OTA_SHA256_SIZE]);
void ota_metadata_confirm_active_app(void);
void ota_metadata_apply_rollback_if_needed(ota_metadata_t *meta);
void ota_metadata_reject_app_b(ota_metadata_t *meta);
uint32_t ota_metadata_selected_app(const ota_metadata_t *meta);

#endif
