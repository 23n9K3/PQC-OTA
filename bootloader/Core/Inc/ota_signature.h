#ifndef OTA_SIGNATURE_H
#define OTA_SIGNATURE_H

#include <stdint.h>

#include "ota_protocol.h"

int ota_signature_verify(const ota_header_t *header,
                         const uint8_t signature[OTA_ML_DSA_65_SIGNATURE_SIZE]);

#endif
