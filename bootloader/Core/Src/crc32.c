#include "crc32.h"

uint32_t crc32_update(uint32_t crc, const void *data, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)data;
    crc = ~crc;

    while (length-- > 0U) {
        crc ^= *bytes++;
        for (uint32_t bit = 0U; bit < 8U; bit++) {
            if ((crc & 1U) != 0U) {
                crc = (crc >> 1U) ^ 0xEDB88320U;
            } else {
                crc >>= 1U;
            }
        }
    }

    return ~crc;
}

uint32_t crc32_compute(const void *data, size_t length)
{
    return crc32_update(0U, data, length);
}
