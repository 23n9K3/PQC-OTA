#ifndef OTA_PROTOCOL_H
#define OTA_PROTOCOL_H

#include <stdint.h>
#include "ota_config.h"
#include "ota_crypto.h"

typedef enum {
    OTA_CMD_START = 0x01,
    OTA_CMD_DATA  = 0x02,
    OTA_CMD_END   = 0x03,
    OTA_CMD_ACK   = 0x79,
    OTA_CMD_ERROR = 0x1F
} ota_cmd_t;

#define OTA_PUBLISHER_ID_SIZE              16U
#define OTA_KEY_ID_SIZE                    16U
#define OTA_ENCRYPTION_KEY_ID_SIZE         16U
#define OTA_GCM_NONCE_SIZE                 12U
#define OTA_GCM_TAG_SIZE                   16U
#define OTA_SIGNATURE_ALGORITHM_ML_DSA_65  1U
#define OTA_ML_DSA_65_SIGNATURE_SIZE       3309U
#define OTA_ENCRYPTION_ALGORITHM_AES_256_GCM 1U

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t header_version;
    uint32_t firmware_version;
    uint32_t firmware_size;
    uint32_t payload_size;
    uint8_t firmware_hash[OTA_SHA256_SIZE];
    uint32_t flags;
    uint8_t publisher_id[OTA_PUBLISHER_ID_SIZE];
    uint8_t key_id[OTA_KEY_ID_SIZE];
    uint32_t signature_algorithm;
    uint32_t signature_size;
    uint32_t encryption_algorithm;
    uint8_t encryption_key_id[OTA_ENCRYPTION_KEY_ID_SIZE];
    uint8_t nonce[OTA_GCM_NONCE_SIZE];
    uint8_t authentication_tag[OTA_GCM_TAG_SIZE];
    uint32_t header_crc32;
} ota_header_t;
#pragma pack(pop)

typedef char ota_header_wire_size_must_be_148[(sizeof(ota_header_t) == 148U) ? 1 : -1];

int ota_header_validate(const ota_header_t *header);

#endif
