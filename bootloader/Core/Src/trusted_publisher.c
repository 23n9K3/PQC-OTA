#include "trusted_publisher.h"

static int constant_time_equal(const uint8_t *a, const uint8_t *b, uint32_t length)
{
    uint32_t i;
    uint8_t difference = 0U;

    for (i = 0U; i < length; ++i) {
        difference |= (uint8_t)(a[i] ^ b[i]);
    }
    return difference == 0U;
}

int trusted_publisher_matches(const uint8_t publisher_id[OTA_PUBLISHER_ID_SIZE],
                              const uint8_t key_id[OTA_KEY_ID_SIZE])
{
    return constant_time_equal(publisher_id, g_trusted_publisher_id, OTA_PUBLISHER_ID_SIZE) &&
           constant_time_equal(key_id, g_trusted_publisher_key_id, OTA_KEY_ID_SIZE);
}
