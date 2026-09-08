#ifndef FLASH_IF_H
#define FLASH_IF_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    FLASH_IF_OK = 0,
    FLASH_IF_ERROR = 1
} flash_if_status_t;

flash_if_status_t flash_if_erase_app_b(void);
flash_if_status_t flash_if_erase_metadata(void);
flash_if_status_t flash_if_write(uint32_t address, const uint8_t *data, uint32_t length, uint8_t pad_final);
int flash_if_is_writable_range(uint32_t address, uint32_t length);

#endif
