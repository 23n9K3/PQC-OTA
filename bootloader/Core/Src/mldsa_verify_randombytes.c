#include "randombytes.h"

#include <string.h>

/*
 * The bootloader only links the ML-DSA verify API.  PQClean's sign.c also
 * contains key-generation/signing entry points, so it references randombytes.
 * Fail closed if one of those unsupported entry points is ever called.
 */
int randombytes(uint8_t *out, size_t outlen)
{
    if (out != NULL) {
        memset(out, 0, outlen);
    }
    return -1;
}

void randombytes_reset_status(void)
{
}

int randombytes_last_status(void)
{
    return -1;
}
