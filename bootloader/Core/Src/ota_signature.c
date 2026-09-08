#include "ota_signature.h"

#include "api.h"
#include "trusted_publisher.h"

#include <stddef.h>

static const uint8_t ota_signature_context[] = "UPQC-OTA-SIGN-V2";

int ota_signature_verify(const ota_header_t *header,
                         const uint8_t signature[OTA_ML_DSA_65_SIGNATURE_SIZE])
{
    if (header == NULL || signature == NULL) {
        return 0;
    }

    if (!trusted_publisher_matches(header->publisher_id, header->key_id)) {
        return 0;
    }

    if (header->signature_algorithm != OTA_SIGNATURE_ALGORITHM_ML_DSA_65 ||
        header->signature_size != PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES) {
        return 0;
    }

    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(
               signature,
               header->signature_size,
               (const uint8_t *)header,
               sizeof(*header),
               ota_signature_context,
               sizeof(ota_signature_context) - 1U,
               g_trusted_publisher_public_key) == 0;
}
