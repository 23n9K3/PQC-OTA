#include "ota_transport_uart.h"

#include "crc32.h"
#include "firmware_decryption_key.h"
#include "flash_if.h"
#include "ota_aes_gcm.h"
#include "ota_config.h"
#include "ota_crypto.h"
#include "ota_metadata.h"
#include "ota_protocol.h"
#include "ota_signature.h"
#include "secure_boot.h"

#include <stdio.h>
#include <string.h>

#define OTA_FRAME_SOF 0xA5U
#define OTA_FRAME_HEADER_SIZE 6U
#define OTA_HEADER_WIRE_SIZE ((uint16_t)sizeof(ota_header_t))

static uint8_t ota_signature_buffer[OTA_ML_DSA_65_SIGNATURE_SIZE];

typedef struct {
    uint8_t cmd;
    uint16_t seq;
    uint16_t length;
    uint8_t payload[OTA_UART_PACKET_MAX];
} ota_frame_t;

static int uart_read_exact(UART_HandleTypeDef *huart, uint8_t *data, uint16_t len, uint32_t timeout)
{
    return HAL_UART_Receive(huart, data, len, timeout) == HAL_OK;
}

static void uart_send_status(UART_HandleTypeDef *huart, uint8_t cmd, uint16_t seq, uint32_t code)
{
    uint8_t frame[1U + 1U + 2U + 2U + 4U + 4U];
    uint32_t crc;
    uint16_t len = 4U;

    frame[0] = OTA_FRAME_SOF;
    frame[1] = cmd;
    frame[2] = (uint8_t)seq;
    frame[3] = (uint8_t)(seq >> 8U);
    frame[4] = (uint8_t)len;
    frame[5] = (uint8_t)(len >> 8U);
    frame[6] = (uint8_t)code;
    frame[7] = (uint8_t)(code >> 8U);
    frame[8] = (uint8_t)(code >> 16U);
    frame[9] = (uint8_t)(code >> 24U);
    crc = crc32_compute(&frame[1], 1U + 2U + 2U + len);
    frame[10] = (uint8_t)crc;
    frame[11] = (uint8_t)(crc >> 8U);
    frame[12] = (uint8_t)(crc >> 16U);
    frame[13] = (uint8_t)(crc >> 24U);

    (void)HAL_UART_Transmit(huart, frame, sizeof(frame), OTA_UART_TIMEOUT_MS);
}

static int uart_read_frame(UART_HandleTypeDef *huart, ota_frame_t *frame)
{
    uint8_t sof;
    uint8_t hdr[OTA_FRAME_HEADER_SIZE - 1U];
    uint8_t crc_buf[4];
    uint32_t recv_crc;
    uint32_t calc_crc;

    if (!uart_read_exact(huart, &sof, 1U, OTA_UART_TIMEOUT_MS)) {
        return 0;
    }

    if (sof != OTA_FRAME_SOF) {
        return -1;
    }

    if (!uart_read_exact(huart, hdr, sizeof(hdr), OTA_UART_TIMEOUT_MS)) {
        return -1;
    }

    frame->cmd = hdr[0];
    frame->seq = (uint16_t)hdr[1] | ((uint16_t)hdr[2] << 8U);
    frame->length = (uint16_t)hdr[3] | ((uint16_t)hdr[4] << 8U);

    if (frame->length > OTA_UART_PACKET_MAX) {
        return -1;
    }

    if (frame->length > 0U) {
        if (!uart_read_exact(huart, frame->payload, frame->length, OTA_UART_TIMEOUT_MS)) {
            return -1;
        }
    }

    if (!uart_read_exact(huart, crc_buf, sizeof(crc_buf), OTA_UART_TIMEOUT_MS)) {
        return -1;
    }

    recv_crc = (uint32_t)crc_buf[0] | ((uint32_t)crc_buf[1] << 8U) |
               ((uint32_t)crc_buf[2] << 16U) | ((uint32_t)crc_buf[3] << 24U);

    calc_crc = crc32_update(0U, hdr, sizeof(hdr));
    calc_crc = crc32_update(calc_crc, frame->payload, frame->length);

    return recv_crc == calc_crc ? 1 : -1;
}

int ota_should_enter_update_mode(UART_HandleTypeDef *huart)
{
    uint8_t ch;

    printf("[OTA] Send 'u' within 1 second to enter OTA mode\r\n");
    if (HAL_UART_Receive(huart, &ch, 1U, 1000U) == HAL_OK) {
        if ((ch == 'u') || (ch == 'U')) {
            printf("[OTA] Enter update mode\r\n");
            return 1;
        }
    }

    return 0;
}

int ota_receive_update_uart(UART_HandleTypeDef *huart)
{
    ota_frame_t frame;
    ota_header_t header;
    ota_header_t gcm_aad_header;
    ota_aes_gcm_ctx_t gcm_ctx;
    ota_sha256_ctx_t sha_ctx;
    ota_metadata_t meta;
    uint8_t final_hash[OTA_SHA256_SIZE];
    uint32_t total_size = 0U;
    uint32_t signature_received = 0U;
    uint32_t payload_received = 0U;
    uint16_t expected_seq = 0U;

    printf("[OTA] Start receiving\r\n");

    if (uart_read_frame(huart, &frame) != 1 || frame.cmd != OTA_CMD_START || frame.length != 4U) {
        printf("[OTA] START failed\r\n");
        uart_send_status(huart, OTA_CMD_ERROR, 0U, 1U);
        return 0;
    }

    total_size = (uint32_t)frame.payload[0] | ((uint32_t)frame.payload[1] << 8U) |
                 ((uint32_t)frame.payload[2] << 16U) | ((uint32_t)frame.payload[3] << 24U);

    if ((total_size < (sizeof(ota_header_t) + OTA_ML_DSA_65_SIGNATURE_SIZE + 1U)) ||
        (total_size > (sizeof(ota_header_t) + OTA_ML_DSA_65_SIGNATURE_SIZE + APP_B_IMAGE_SIZE))) {
        printf("[OTA] Invalid OTA size: %lu\r\n", total_size);
        uart_send_status(huart, OTA_CMD_ERROR, frame.seq, 2U);
        return 0;
    }

    uart_send_status(huart, OTA_CMD_ACK, frame.seq, 0U);

    if (uart_read_frame(huart, &frame) != 1 || frame.cmd != OTA_CMD_DATA ||
        frame.seq != expected_seq || frame.length != OTA_HEADER_WIRE_SIZE) {
        printf("[OTA] Header DATA failed\r\n");
        uart_send_status(huart, OTA_CMD_ERROR, expected_seq, 3U);
        return 0;
    }

    memcpy(&header, frame.payload, sizeof(header));
    if (!ota_header_validate(&header)) {
        printf("[OTA] Header validate failed\r\n");
        uart_send_status(huart, OTA_CMD_ERROR, frame.seq, 4U);
        return 0;
    }

    if (total_size != (sizeof(header) + header.signature_size + header.payload_size)) {
        printf("[OTA] Signed package size mismatch\r\n");
        uart_send_status(huart, OTA_CMD_ERROR, frame.seq, 12U);
        return 0;
    }

    if (memcmp(header.encryption_key_id, g_firmware_aes256_key_id,
               OTA_ENCRYPTION_KEY_ID_SIZE) != 0) {
        printf("[AES-GCM] Encryption key id mismatch\r\n");
        uart_send_status(huart, OTA_CMD_ERROR, frame.seq, 18U);
        return 0;
    }

    printf("[OTA] Signed Header ok, fw_size=%lu version=%lu publisher=%.16s\r\n",
           header.firmware_size, header.firmware_version, header.publisher_id);
    uart_send_status(huart, OTA_CMD_ACK, frame.seq, 0U);
    expected_seq++;

    while (signature_received < header.signature_size) {
        uint32_t remaining = header.signature_size - signature_received;

        if (uart_read_frame(huart, &frame) != 1 || frame.cmd != OTA_CMD_DATA ||
            frame.seq != expected_seq || frame.length == 0U || frame.length > remaining) {
            printf("[SEC] Signature DATA failed, expect seq=%u\r\n", expected_seq);
            uart_send_status(huart, OTA_CMD_ERROR, expected_seq, 13U);
            return 0;
        }

        memcpy(&ota_signature_buffer[signature_received], frame.payload, frame.length);
        signature_received += frame.length;

        if (signature_received == header.signature_size) {
            printf("[SEC] Verify ML-DSA-65 publisher signature\r\n");
            if (!ota_signature_verify(&header, ota_signature_buffer)) {
                printf("[SEC] Publisher authentication FAILED\r\n");
                uart_send_status(huart, OTA_CMD_ERROR, frame.seq, 14U);
                return 0;
            }

            printf("[SEC] Publisher authentication OK\r\n");

            /* The tag and CRC fields are zero in the canonical AES-GCM AAD. */
            memcpy(&gcm_aad_header, &header, sizeof(gcm_aad_header));
            memset(gcm_aad_header.authentication_tag, 0,
                   sizeof(gcm_aad_header.authentication_tag));
            gcm_aad_header.header_crc32 = 0U;
            if (!ota_aes_gcm_decrypt_init(&gcm_ctx, g_firmware_aes256_key,
                                          header.nonce,
                                          (const uint8_t *)&gcm_aad_header,
                                          sizeof(gcm_aad_header))) {
                printf("[AES-GCM] Decrypt init failed\r\n");
                uart_send_status(huart, OTA_CMD_ERROR, frame.seq, 19U);
                return 0;
            }

            if (flash_if_erase_app_b() != FLASH_IF_OK) {
                uart_send_status(huart, OTA_CMD_ERROR, frame.seq, 5U);
                return 0;
            }
        }

        uart_send_status(huart, OTA_CMD_ACK, frame.seq, signature_received);
        expected_seq++;
    }

    ota_sha256_init(&sha_ctx);

    while (payload_received < header.payload_size) {
        uint8_t is_final;

        if (uart_read_frame(huart, &frame) != 1 || frame.cmd != OTA_CMD_DATA || frame.seq != expected_seq) {
            printf("[OTA] DATA failed, expect seq=%u\r\n", expected_seq);
            uart_send_status(huart, OTA_CMD_ERROR, expected_seq, 6U);
            return 0;
        }

        if ((frame.length == 0U) ||
            ((payload_received + frame.length) > header.payload_size)) {
            printf("[OTA] DATA overflow\r\n");
            uart_send_status(huart, OTA_CMD_ERROR, frame.seq, 7U);
            return 0;
        }

        /* Authenticate ciphertext and decrypt in place before writing plaintext. */
        ota_aes_gcm_decrypt_update(&gcm_ctx, frame.payload, frame.payload,
                                   frame.length);
        is_final = ((payload_received + frame.length) == header.payload_size) ? 1U : 0U;
        if (flash_if_write(APP_B_START_ADDR + payload_received, frame.payload, frame.length, is_final) != FLASH_IF_OK) {
            uart_send_status(huart, OTA_CMD_ERROR, frame.seq, 8U);
            return 0;
        }

        ota_sha256_update(&sha_ctx, frame.payload, frame.length);
        payload_received += frame.length;
        uart_send_status(huart, OTA_CMD_ACK, frame.seq, payload_received);
        expected_seq++;
    }

    if (uart_read_frame(huart, &frame) != 1 || frame.cmd != OTA_CMD_END) {
        printf("[OTA] END failed\r\n");
        uart_send_status(huart, OTA_CMD_ERROR, expected_seq, 9U);
        return 0;
    }

    ota_sha256_final(&sha_ctx, final_hash);
    if (!ota_aes_gcm_decrypt_final(&gcm_ctx, header.authentication_tag)) {
        printf("[AES-GCM] Authentication tag FAILED\r\n");
        uart_send_status(huart, OTA_CMD_ERROR, frame.seq, 20U);
        return 0;
    }
    printf("[AES-GCM] Authentication tag OK\r\n");

    if (!ota_hash_equal(final_hash, header.firmware_hash)) {
        printf("[OTA] Hash verify failed\r\n");
        uart_send_status(huart, OTA_CMD_ERROR, frame.seq, 10U);
        return 0;
    }

    /*
     * Persist the authenticated Header and signature in the slot's reserved
     * 4 KB Manifest page.  Signature starts at an 8-byte aligned offset so
     * STM32 double-word Flash programming remains valid.
     */
    printf("[SECURE BOOT] Write App B Manifest\r\n");
    if (flash_if_write(APP_B_MANIFEST_ADDR, (const uint8_t *)&header,
                       sizeof(header), 1U) != FLASH_IF_OK) {
        uart_send_status(huart, OTA_CMD_ERROR, frame.seq, 15U);
        return 0;
    }
    if (flash_if_write(APP_B_MANIFEST_ADDR + APP_MANIFEST_SIGNATURE_OFFSET,
                       ota_signature_buffer, header.signature_size, 1U) != FLASH_IF_OK) {
        uart_send_status(huart, OTA_CMD_ERROR, frame.seq, 16U);
        return 0;
    }

    if (!secure_boot_verify_app(APP_B_START_ADDR)) {
        printf("[SECURE BOOT] Installed App B verification failed\r\n");
        uart_send_status(huart, OTA_CMD_ERROR, frame.seq, 17U);
        return 0;
    }

    ota_metadata_load_or_init(&meta);
    ota_metadata_prepare_app_b(&meta, header.firmware_size, header.firmware_hash);
    if (!ota_metadata_save(&meta)) {
        uart_send_status(huart, OTA_CMD_ERROR, frame.seq, 11U);
        return 0;
    }

    printf("[OTA] OTA SUCCESS\r\n");
    printf("[OTA] Reboot to App B\r\n");
    uart_send_status(huart, OTA_CMD_ACK, frame.seq, 0U);
    HAL_Delay(200U);
    NVIC_SystemReset();
    return 1;
}

void ota_wait_for_update(UART_HandleTypeDef *huart)
{
    while (1) {
        if (ota_should_enter_update_mode(huart)) {
            (void)ota_receive_update_uart(huart);
        }
        HAL_Delay(100U);
    }
}
