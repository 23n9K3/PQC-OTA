#ifndef FIRMWARE_DECRYPTION_KEY_H
#define FIRMWARE_DECRYPTION_KEY_H

#include <stdint.h>

#define FIRMWARE_AES256_KEY_SIZE 32U
#define FIRMWARE_AES_KEY_ID_SIZE 16U

extern const uint8_t g_firmware_aes256_key[FIRMWARE_AES256_KEY_SIZE];
extern const uint8_t g_firmware_aes256_key_id[FIRMWARE_AES_KEY_ID_SIZE];

#endif
