#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

#ifndef MLDSA_USE_DETERMINISTIC_TEST_RNG
#define MLDSA_USE_DETERMINISTIC_TEST_RNG 0
#endif

int randombytes(uint8_t *out, size_t outlen);
void randombytes_reset_status(void);
int randombytes_last_status(void);

#endif
