#include "secure_boot.h"

#include "ota_config.h"
#include "ota_crypto.h"
#include "ota_protocol.h"
#include "ota_signature.h"

#include <stdio.h>
#include <string.h>

static uint32_t secure_boot_manifest_addr(uint32_t app_addr)
{
    if (app_addr == APP_A_START_ADDR) {
        return APP_A_MANIFEST_ADDR;
    }
    if (app_addr == APP_B_START_ADDR) {
        return APP_B_MANIFEST_ADDR;
    }
    return 0U;
}

static uint32_t secure_boot_image_capacity(uint32_t app_addr)
{
    if (app_addr == APP_A_START_ADDR) {
        return APP_A_IMAGE_SIZE;
    }
    if (app_addr == APP_B_START_ADDR) {
        return APP_B_IMAGE_SIZE;
    }
    return 0U;
}

int secure_boot_verify_app(uint32_t app_addr)
{
    uint32_t manifest_addr = secure_boot_manifest_addr(app_addr);
    uint32_t image_capacity = secure_boot_image_capacity(app_addr);
    ota_header_t header;
    uint8_t actual_hash[OTA_SHA256_SIZE];
    const uint8_t *signature;

    if ((manifest_addr == 0U) || (image_capacity == 0U)) {
        printf("[SECURE BOOT] Unknown app slot: 0x%08lX\r\n", app_addr);
        return 0;
    }

    memcpy(&header, (const void *)manifest_addr, sizeof(header));
    signature = (const uint8_t *)(manifest_addr + APP_MANIFEST_SIGNATURE_OFFSET);

    printf("[SECURE BOOT] Verify app at 0x%08lX\r\n", app_addr);

    if (!ota_header_validate(&header) ||
        (header.firmware_size < 8U) ||
        (header.firmware_size > image_capacity)) {
        printf("[SECURE BOOT] Manifest invalid\r\n");
        return 0;
    }

    if (!ota_signature_verify(&header, signature)) {
        printf("[SECURE BOOT] Publisher signature invalid\r\n");
        return 0;
    }

    ota_sha256_compute((const uint8_t *)app_addr, header.firmware_size, actual_hash);
    if (!ota_hash_equal(actual_hash, header.firmware_hash)) {
        printf("[SECURE BOOT] App SHA-256 mismatch\r\n");
        return 0;
    }

    printf("[SECURE BOOT] PASS publisher=%.16s version=%lu size=%lu\r\n",
           header.publisher_id, header.firmware_version, header.firmware_size);
    return 1;
}
