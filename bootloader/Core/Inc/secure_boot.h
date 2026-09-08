#ifndef SECURE_BOOT_H
#define SECURE_BOOT_H

#include <stdint.h>

int secure_boot_verify_app(uint32_t app_addr);

#endif
