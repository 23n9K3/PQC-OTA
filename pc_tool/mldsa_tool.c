#include "api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t k_ota_context[] = "UPQC-OTA-SIGN-V2";

static void secure_zero(void *buffer, size_t length)
{
    volatile uint8_t *p = (volatile uint8_t *)buffer;
    while (length-- != 0U) *p++ = 0U;
}

static int read_file(const char *path, uint8_t **data, size_t *length)
{
    FILE *file;
    long size;
    uint8_t *buffer;

    file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0) {
        if (file != NULL) fclose(file);
        return -1;
    }
    size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }
    buffer = (uint8_t *)malloc(size == 0 ? 1U : (size_t)size);
    if (buffer == NULL || fread(buffer, 1, (size_t)size, file) != (size_t)size) {
        free(buffer);
        fclose(file);
        return -1;
    }
    fclose(file);
    *data = buffer;
    *length = (size_t)size;
    return 0;
}

static int write_file(const char *path, const uint8_t *data, size_t length)
{
    FILE *file = fopen(path, "wb");
    if (file == NULL) return -1;
    if (fwrite(data, 1, length, file) != length) {
        fclose(file);
        return -1;
    }
    return fclose(file) == 0 ? 0 : -1;
}

static int keygen(const char *public_path, const char *secret_path)
{
    uint8_t *pk = (uint8_t *)malloc(PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES);
    uint8_t *sk = (uint8_t *)malloc(PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES);
    int rc = -1;

    if (pk != NULL && sk != NULL && PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk) == 0 &&
        write_file(public_path, pk, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES) == 0 &&
        write_file(secret_path, sk, PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES) == 0) {
        rc = 0;
    }
    if (sk != NULL) secure_zero(sk, PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES);
    free(sk);
    free(pk);
    return rc;
}

static int sign_file(const char *secret_path, const char *message_path, const char *signature_path)
{
    uint8_t *sk = NULL;
    uint8_t *message = NULL;
    uint8_t signature[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES];
    size_t sk_len = 0;
    size_t message_len = 0;
    size_t signature_len = 0;
    int rc = -1;

    if (read_file(secret_path, &sk, &sk_len) != 0 ||
        sk_len != PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES ||
        read_file(message_path, &message, &message_len) != 0) goto cleanup;

    if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(
            signature, &signature_len, message, message_len,
            k_ota_context, sizeof(k_ota_context) - 1U, sk) != 0 ||
        signature_len != sizeof(signature)) goto cleanup;

    rc = write_file(signature_path, signature, signature_len);

cleanup:
    if (sk != NULL) secure_zero(sk, sk_len);
    free(message);
    free(sk);
    return rc;
}

static int verify_file(const char *public_path, const char *message_path, const char *signature_path)
{
    uint8_t *pk = NULL;
    uint8_t *message = NULL;
    uint8_t *signature = NULL;
    size_t pk_len = 0, message_len = 0, signature_len = 0;
    int rc = -1;

    if (read_file(public_path, &pk, &pk_len) != 0 ||
        pk_len != PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES ||
        read_file(message_path, &message, &message_len) != 0 ||
        read_file(signature_path, &signature, &signature_len) != 0 ||
        signature_len != PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES) goto cleanup;

    rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(
        signature, signature_len, message, message_len,
        k_ota_context, sizeof(k_ota_context) - 1U, pk);

cleanup:
    free(signature);
    free(message);
    free(pk);
    return rc;
}

static void usage(const char *program)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s keygen <public.bin> <secret.bin>\n"
        "  %s sign <secret.bin> <message.bin> <signature.bin>\n"
        "  %s verify <public.bin> <message.bin> <signature.bin>\n",
        program, program, program);
}

int main(int argc, char **argv)
{
    int rc;
    if (argc != 5 && !(argc == 4 && strcmp(argv[1], "keygen") == 0)) {
        usage(argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "keygen") == 0) {
        rc = keygen(argv[2], argv[3]);
    } else if (strcmp(argv[1], "sign") == 0 && argc == 5) {
        rc = sign_file(argv[2], argv[3], argv[4]);
    } else if (strcmp(argv[1], "verify") == 0 && argc == 5) {
        rc = verify_file(argv[2], argv[3], argv[4]);
    } else {
        usage(argv[0]);
        return 2;
    }
    if (rc != 0) {
        fprintf(stderr, "ML-DSA operation failed\n");
        return 1;
    }
    puts("ML-DSA operation successful");
    return 0;
}
