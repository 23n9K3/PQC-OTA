#include "randombytes.h"

#include <windows.h>
#include <wincrypt.h>

static void secure_zero(void *buffer, size_t length)
{
    volatile uint8_t *p = (volatile uint8_t *)buffer;
    while (length-- != 0U) *p++ = 0U;
}

int randombytes(uint8_t *out, size_t outlen)
{
    HCRYPTPROV provider = 0;

    if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        secure_zero(out, outlen);
        return -1;
    }

    while (outlen != 0U) {
        DWORD chunk = outlen > 0xFFFFFFFFU ? 0xFFFFFFFFU : (DWORD)outlen;
        if (!CryptGenRandom(provider, chunk, out)) {
            secure_zero(out, outlen);
            CryptReleaseContext(provider, 0);
            return -1;
        }
        out += chunk;
        outlen -= chunk;
    }
    CryptReleaseContext(provider, 0);
    return 0;
}

void randombytes_reset_status(void)
{
}

int randombytes_last_status(void)
{
    return 0;
}
