#include "ota_protocol.h"
#include "crc32.h"

#include <string.h>

int ota_header_validate(const ota_header_t *header)
{
    ota_header_t tmp;
    uint32_t crc;

    if (header->magic != OTA_FILE_MAGIC) {
        return 0;
    }

    if (header->header_version != OTA_HEADER_VERSION) {
        return 0;
    }

    if ((header->firmware_size == 0U) || (header->payload_size != header->firmware_size)) {
        return 0;
    }

    if (header->firmware_size > APP_B_IMAGE_SIZE) {
        return 0;
    }

    if (header->signature_algorithm != OTA_SIGNATURE_ALGORITHM_ML_DSA_65 ||
        header->signature_size != OTA_ML_DSA_65_SIGNATURE_SIZE) {
        return 0;
    }

    if (header->encryption_algorithm != OTA_ENCRYPTION_ALGORITHM_AES_256_GCM) {
        return 0;
    }

    memcpy(&tmp, header, sizeof(tmp));
    tmp.header_crc32 = 0U;
    crc = crc32_compute(&tmp, sizeof(tmp));

    return crc == header->header_crc32;
}
