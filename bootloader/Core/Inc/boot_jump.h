#ifndef BOOT_JUMP_H
#define BOOT_JUMP_H

#include <stdint.h>

void boot_jump_to_app(uint32_t app_addr);
int boot_is_valid_app(uint32_t app_addr);

#endif
