#ifndef TRUSTED_PUBLISHER_H
#define TRUSTED_PUBLISHER_H

#include <stdint.h>

#include "ota_protocol.h"

#define TRUSTED_ML_DSA_65_PUBLIC_KEY_SIZE 1952U

extern const uint8_t g_trusted_publisher_id[OTA_PUBLISHER_ID_SIZE];
extern const uint8_t g_trusted_publisher_key_id[OTA_KEY_ID_SIZE];
extern const uint8_t g_trusted_publisher_public_key[TRUSTED_ML_DSA_65_PUBLIC_KEY_SIZE];

int trusted_publisher_matches(const uint8_t publisher_id[OTA_PUBLISHER_ID_SIZE],
                              const uint8_t key_id[OTA_KEY_ID_SIZE]);

#endif
