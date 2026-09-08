#include "ota_metadata.h"

#include "crc32.h"
#include "flash_if.h"
#include "ota_config.h"

#include <stdio.h>
#include <string.h>

static uint32_t ota_metadata_crc(const ota_metadata_t *meta)
{
    ota_metadata_t tmp;
    memcpy(&tmp, meta, sizeof(tmp));
    tmp.crc32 = 0U;
    return crc32_compute(&tmp, sizeof(tmp));
}

static void ota_metadata_set_default(ota_metadata_t *meta)
{
    memset(meta, 0, sizeof(*meta));
    meta->magic = OTA_METADATA_MAGIC;
    meta->active_slot = OTA_SLOT_A;
    meta->app_a_valid = OTA_VALID;
    meta->app_b_valid = OTA_INVALID;
    meta->pending_verify = 0U;
    meta->boot_count = 0U;
    meta->crc32 = ota_metadata_crc(meta);
}

void ota_metadata_load_or_init(ota_metadata_t *meta)
{
    const ota_metadata_t *stored = (const ota_metadata_t *)OTA_METADATA_ADDR;

    memcpy(meta, stored, sizeof(*meta));

    if ((meta->magic != OTA_METADATA_MAGIC) || (meta->crc32 != ota_metadata_crc(meta))) {
        printf("[BOOT] Metadata empty or CRC error, init default\r\n");
        ota_metadata_set_default(meta);
        if (!ota_metadata_save(meta)) {
            printf("[BOOT] Metadata init save failed\r\n");
        }
        return;
    }

    printf("[BOOT] Metadata loaded\r\n");
}

int ota_metadata_save(ota_metadata_t *meta)
{
    meta->magic = OTA_METADATA_MAGIC;
    meta->crc32 = ota_metadata_crc(meta);

    if (flash_if_erase_metadata() != FLASH_IF_OK) {
        printf("[BOOT] Metadata erase failed\r\n");
        return 0;
    }

    if (flash_if_write(OTA_METADATA_ADDR, (const uint8_t *)meta, sizeof(*meta), 1U) != FLASH_IF_OK) {
        printf("[BOOT] Metadata write failed\r\n");
        return 0;
    }

    printf("[BOOT] Metadata saved\r\n");
    return 1;
}

void ota_metadata_prepare_app_b(ota_metadata_t *meta, uint32_t size, const uint8_t hash[OTA_SHA256_SIZE])
{
    meta->active_slot = OTA_SLOT_B;
    meta->app_b_valid = OTA_VALID;
    meta->pending_verify = 1U;
    meta->boot_count = 0U;
    meta->app_b_size = size;
    memcpy(meta->app_b_hash, hash, OTA_SHA256_SIZE);
}

void ota_metadata_confirm_active_app(void)
{
    ota_metadata_t meta;
    ota_metadata_load_or_init(&meta);

    if (meta.pending_verify != 0U) {
        meta.pending_verify = 0U;
        meta.boot_count = 0U;
        (void)ota_metadata_save(&meta);
    }
}

void ota_metadata_apply_rollback_if_needed(ota_metadata_t *meta)
{
    if ((meta->active_slot == OTA_SLOT_B) && (meta->pending_verify != 0U)) {
        if (meta->boot_count >= OTA_MAX_BOOT_COUNT) {
            printf("[BOOT] App B verify timeout, rollback to App A\r\n");
            meta->active_slot = OTA_SLOT_A;
            meta->app_b_valid = OTA_INVALID;
            meta->pending_verify = 0U;
            meta->boot_count = 0U;
            (void)ota_metadata_save(meta);
            return;
        }

        meta->boot_count++;
        printf("[BOOT] App B pending verify, boot_count=%lu\r\n", meta->boot_count);
        (void)ota_metadata_save(meta);
    }
}

void ota_metadata_reject_app_b(ota_metadata_t *meta)
{
    meta->active_slot = OTA_SLOT_A;
    meta->app_b_valid = OTA_INVALID;
    meta->pending_verify = 0U;
    meta->boot_count = 0U;
    (void)ota_metadata_save(meta);
}

uint32_t ota_metadata_selected_app(const ota_metadata_t *meta)
{
    if ((meta->active_slot == OTA_SLOT_B) && (meta->app_b_valid == OTA_VALID)) {
        return APP_B_START_ADDR;
    }

    return APP_A_START_ADDR;
}
