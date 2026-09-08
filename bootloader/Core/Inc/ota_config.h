#ifndef OTA_CONFIG_H
#define OTA_CONFIG_H

#include <stdint.h>

/* Flash 分区：STM32L4R5ZIT6P 按 2 MB Flash 规划。 */
#define FLASH_BASE_ADDR       0x08000000U
#define BOOTLOADER_START      0x08000000U
#define BOOTLOADER_SIZE       0x00020000U

#define APP_A_START_ADDR      0x08020000U
#define APP_A_SIZE            0x000E0000U
#define APP_A_MANIFEST_ADDR   0x080FF000U
#define APP_A_IMAGE_SIZE      0x000DF000U

#define APP_B_START_ADDR      0x08100000U
#define APP_B_SIZE            0x000E0000U
#define APP_B_MANIFEST_ADDR   0x081DF000U
#define APP_B_IMAGE_SIZE      0x000DF000U

/* 每个 App slot 的最后 4 KB 保存 Secure Boot Manifest。 */
#define APP_MANIFEST_PAGE_SIZE 0x00001000U
#define APP_MANIFEST_SIGNATURE_OFFSET 152U

#define OTA_METADATA_ADDR     0x081E0000U
#define OTA_METADATA_SIZE     0x00020000U

#define FLASH_END_ADDR        0x08200000U

/* SRAM 范围用于检查 App 向量表里的初始 MSP。STM32L4R5 SRAM 起点为 0x20000000。 */
#define SRAM_BASE_ADDR        0x20000000U
#define SRAM_END_ADDR         0x200A0000U

#define OTA_METADATA_MAGIC    0x4F54414DU
#define OTA_FILE_MAGIC        0x31544F55U
#define OTA_HEADER_VERSION    3U

#define OTA_SLOT_A            0U
#define OTA_SLOT_B            1U
#define OTA_VALID             1U
#define OTA_INVALID           0U
#define OTA_MAX_BOOT_COUNT    3U

/* OTA v3：AES-256-GCM 机密性/认证 + SHA-256 + ML-DSA-65 发布者认证。 */
#define DEMO_HASH_ONLY        0
#define ENABLE_AES_GCM        1
#define ENABLE_ML_DSA_VERIFY  1
#define ENABLE_SECURE_BOOT     1

#define OTA_UART_TIMEOUT_MS   3000U
#define OTA_UART_PACKET_MAX   512U

#endif
