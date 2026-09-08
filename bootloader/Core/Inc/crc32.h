#ifndef CRC32_H
#define CRC32_H

#include <stdint.h>
#include <stddef.h>

/* 计算标准 CRC32，初值和异或值均按常见 ZIP/Ethernet 方式处理。 */
uint32_t crc32_compute(const void *data, size_t length);
uint32_t crc32_update(uint32_t crc, const void *data, size_t length);

#endif
