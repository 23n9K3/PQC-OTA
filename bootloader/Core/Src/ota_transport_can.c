#include "ota_transport_can.h"

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

#define OTA_CAN_FRAME_TIMEOUT_MS 3000U
#define OTA_CAN_ENTRY_TIMEOUT_MS 1000U
#define OTA_CAN_FLASH_BUFFER_SIZE 256U
#define OTA_CAN_DEBUG_FIRST_FRAMES 4U
#define OTA_CAN_DEBUG_FRAME_INTERVAL 128U
#define OTA_CAN_DEBUG_FLASH_INTERVAL 4096U

typedef struct {
    uint8_t cmd;
    uint16_t seq;
    uint8_t length;
    uint8_t payload[OTA_CAN_DATA_BYTES];
} ota_can_frame_t;

static uint8_t ota_can_signature_buffer[OTA_ML_DSA_65_SIGNATURE_SIZE];
static uint32_t ota_can_pending_total_size;

static const char *can_command_name(uint8_t cmd)
{
    switch (cmd) {
    case OTA_CMD_START: return "START";
    case OTA_CMD_DATA:  return "DATA";
    case OTA_CMD_END:   return "END";
    case OTA_CMD_ACK:   return "ACK";
    case OTA_CMD_ERROR: return "ERROR";
    default:            return "UNKNOWN";
    }
}

static void can_print_hex(const char *label, const uint8_t *data,
                          uint32_t length)
{
    uint32_t i;

    printf("%s", label);
    for (i = 0U; i < length; i++) {
        printf("%02X", data[i]);
    }
    printf("\r\n");
}

static void can_log_request(const char *prefix, const ota_can_frame_t *frame)
{
    uint32_t i;

    printf("[OTA-CAN][RX] %s cmd=%s(0x%02X) seq=%u len=%u data=",
           prefix, can_command_name(frame->cmd), frame->cmd,
           frame->seq, frame->length);
    for (i = 0U; i < frame->length; i++) {
        printf("%02X", frame->payload[i]);
        if ((i + 1U) < frame->length) printf(" ");
    }
    printf("\r\n");
}

static int timeout_elapsed(uint32_t start, uint32_t timeout)
{
    return (uint32_t)(HAL_GetTick() - start) >= timeout;
}

static int can_read_request(CAN_HandleTypeDef *hcan, ota_can_frame_t *frame,
                            uint32_t timeout)
{
    CAN_RxHeaderTypeDef header;
    uint8_t data[8];
    uint32_t start = HAL_GetTick();

    while (!timeout_elapsed(start, timeout)) {
        if (HAL_CAN_GetRxFifoFillLevel(hcan, CAN_RX_FIFO0) == 0U) {
            continue;
        }
        if (HAL_CAN_GetRxMessage(hcan, CAN_RX_FIFO0, &header, data) != HAL_OK) {
            printf("[OTA-CAN][RX] HAL_CAN_GetRxMessage failed, error=0x%08lX\r\n",
                   HAL_CAN_GetError(hcan));
            return 0;
        }
        if ((header.IDE != CAN_ID_STD) || (header.RTR != CAN_RTR_DATA) ||
            (header.StdId != OTA_CAN_REQUEST_ID) || (header.DLC < 4U)) {
            continue;
        }

        frame->cmd = data[0];
        frame->seq = (uint16_t)data[1] | ((uint16_t)data[2] << 8U);
        frame->length = data[3];
        if ((frame->length > OTA_CAN_DATA_BYTES) ||
            (header.DLC != (uint32_t)(4U + frame->length))) {
            printf("[OTA-CAN][RX] Malformed request: id=0x%03lX dlc=%lu "
                   "cmd=0x%02X seq=%u payload_len=%u\r\n",
                   header.StdId, header.DLC, frame->cmd,
                   frame->seq, frame->length);
            return 0;
        }
        if (frame->length != 0U) {
            memcpy(frame->payload, &data[4], frame->length);
        }
        return 1;
    }
    return 0;
}

static int can_send_status(CAN_HandleTypeDef *hcan, uint8_t cmd,
                           uint16_t seq, uint32_t code)
{
    CAN_TxHeaderTypeDef header;
    uint8_t data[7];
    uint32_t mailbox;
    uint32_t start = HAL_GetTick();

    memset(&header, 0, sizeof(header));
    header.StdId = OTA_CAN_STATUS_ID;
    header.IDE = CAN_ID_STD;
    header.RTR = CAN_RTR_DATA;
    header.DLC = sizeof(data);
    header.TransmitGlobalTime = DISABLE;

    data[0] = cmd;
    data[1] = (uint8_t)seq;
    data[2] = (uint8_t)(seq >> 8U);
    data[3] = (uint8_t)code;
    data[4] = (uint8_t)(code >> 8U);
    data[5] = (uint8_t)(code >> 16U);
    data[6] = (uint8_t)(code >> 24U);

    while (HAL_CAN_GetTxMailboxesFreeLevel(hcan) == 0U) {
        if (timeout_elapsed(start, OTA_CAN_FRAME_TIMEOUT_MS)) {
            printf("[OTA-CAN][TX] No free mailbox: cmd=%s seq=%u\r\n",
                   can_command_name(cmd), seq);
            return 0;
        }
    }
    if (HAL_CAN_AddTxMessage(hcan, &header, data, &mailbox) != HAL_OK) {
        printf("[OTA-CAN][TX] HAL_CAN_AddTxMessage failed: cmd=%s seq=%u "
               "error=0x%08lX\r\n",
               can_command_name(cmd), seq, HAL_CAN_GetError(hcan));
        return 0;
    }
    while (HAL_CAN_IsTxMessagePending(hcan, mailbox) != 0U) {
        if (timeout_elapsed(start, OTA_CAN_FRAME_TIMEOUT_MS)) {
            printf("[OTA-CAN][TX] Transmit timeout: cmd=%s seq=%u "
                   "error=0x%08lX\r\n",
                   can_command_name(cmd), seq, HAL_CAN_GetError(hcan));
            return 0;
        }
    }
    if (cmd == OTA_CMD_ERROR) {
        printf("[OTA-CAN][TX] ERROR seq=%u code=%lu\r\n", seq, code);
    }
    return 1;
}

static uint32_t load_le32(const uint8_t value[4])
{
    return (uint32_t)value[0] | ((uint32_t)value[1] << 8U) |
           ((uint32_t)value[2] << 16U) | ((uint32_t)value[3] << 24U);
}

int ota_can_should_enter_update_mode(CAN_HandleTypeDef *hcan)
{
    ota_can_frame_t frame;
    int received;

    printf("[OTA-CAN][FLOW] ID request=0x%03X status=0x%03X, "
           "classic CAN payload=%u bytes\r\n",
           OTA_CAN_REQUEST_ID, OTA_CAN_STATUS_ID, OTA_CAN_DATA_BYTES);
    printf("[OTA-CAN][FLOW] Wait %lu ms for START\r\n",
           OTA_CAN_ENTRY_TIMEOUT_MS);
    received = can_read_request(hcan, &frame, OTA_CAN_ENTRY_TIMEOUT_MS);
    if (received && (frame.cmd == OTA_CMD_START) && (frame.length == 4U)) {
        can_log_request("accepted", &frame);
        ota_can_pending_total_size = load_le32(frame.payload);
        printf("[OTA-CAN][FLOW] Enter OTA mode: stream=%lu bytes, "
               "expected DATA frames=%lu\r\n",
               ota_can_pending_total_size,
               (ota_can_pending_total_size + OTA_CAN_DATA_BYTES - 1U) /
               OTA_CAN_DATA_BYTES);
        (void)can_send_status(hcan, OTA_CMD_ACK, frame.seq, 0U);
        printf("[OTA-CAN][TX] ACK START seq=%u value=0\r\n", frame.seq);
        return 1;
    }
    if (received) {
        can_log_request("ignored while waiting START", &frame);
    } else {
        printf("[OTA-CAN][FLOW] START window expired; continue normal boot\r\n");
    }
    return 0;
}

int ota_receive_update_can(CAN_HandleTypeDef *hcan)
{
    ota_can_frame_t frame;
    ota_header_t header;
    ota_header_t aad_header;
    ota_aes_gcm_ctx_t gcm_ctx;
    ota_sha256_ctx_t sha_ctx;
    ota_metadata_t meta;
    uint8_t final_hash[OTA_SHA256_SIZE];
    uint8_t flash_buffer[OTA_CAN_FLASH_BUFFER_SIZE];
    uint8_t plain[OTA_CAN_DATA_BYTES];
    uint32_t total_size = ota_can_pending_total_size;
    uint32_t stream_received = 0U;
    uint32_t header_received = 0U;
    uint32_t signature_received = 0U;
    uint32_t payload_received = 0U;
    uint32_t flash_buffer_len = 0U;
    uint32_t flash_written = 0U;
    uint32_t next_flash_report = OTA_CAN_DEBUG_FLASH_INTERVAL;
    uint32_t next_progress = 10U;
    uint32_t update_start = HAL_GetTick();
    uint32_t data_frames_received = 0U;
    uint16_t expected_seq = 0U;
    uint8_t crypto_ready = 0U;

    if ((total_size < (sizeof(header) + OTA_ML_DSA_65_SIGNATURE_SIZE + 1U)) ||
        (total_size > (sizeof(header) + OTA_ML_DSA_65_SIGNATURE_SIZE + APP_B_IMAGE_SIZE))) {
        printf("[OTA-CAN] Invalid OTA size: %lu\r\n", total_size);
        return 0;
    }

    memset(&header, 0, sizeof(header));
    printf("[OTA-CAN][FLOW] Phase 1: receive OTA Header (%lu bytes)\r\n",
           (uint32_t)sizeof(header));

    while (stream_received < total_size) {
        uint32_t offset = 0U;

        if (!can_read_request(hcan, &frame, OTA_CAN_FRAME_TIMEOUT_MS)) {
            printf("[OTA-CAN] DATA timeout or malformed frame, expect seq=%u\r\n",
                   expected_seq);
            (void)can_send_status(hcan, OTA_CMD_ERROR, expected_seq, 6U);
            return 0;
        }

        /* PC CAN adapters may queue/retry START while the MCU is in reset.
         * Ignore any stale duplicate after update mode has already started.
         * START uses sequence 0xFFFF in the current PC tool, so its ACK can
         * never be mistaken for the acknowledgement of DATA sequence 0. */
        if ((frame.cmd == OTA_CMD_START) && (frame.length == 4U) &&
            (load_le32(frame.payload) == total_size)) {
            can_log_request("duplicate ignored", &frame);
            continue;
        }

        if ((frame.cmd != OTA_CMD_DATA) || (frame.seq != expected_seq) ||
            (frame.length == 0U) ||
            ((stream_received + frame.length) > total_size)) {
            printf("[OTA-CAN] DATA rejected: cmd=0x%02X seq=%u len=%u, "
                   "expect seq=%u remaining=%lu\r\n",
                   frame.cmd, frame.seq, frame.length, expected_seq,
                   total_size - stream_received);
            (void)can_send_status(hcan, OTA_CMD_ERROR, expected_seq, 6U);
            return 0;
        }

        if (((uint32_t)expected_seq < OTA_CAN_DEBUG_FIRST_FRAMES) ||
            (((uint32_t)expected_seq % OTA_CAN_DEBUG_FRAME_INTERVAL) == 0U) ||
            ((stream_received + frame.length) == total_size)) {
            can_log_request("sample", &frame);
        }

        while (offset < frame.length) {
            if (header_received < sizeof(header)) {
                uint32_t take = sizeof(header) - header_received;
                if (take > (frame.length - offset)) take = frame.length - offset;
                memcpy(((uint8_t *)&header) + header_received,
                       &frame.payload[offset], take);
                header_received += take;
                offset += take;

                if (header_received == sizeof(header)) {
                    if (!ota_header_validate(&header) ||
                        (total_size != (sizeof(header) + header.signature_size +
                                        header.payload_size))) {
                        printf("[OTA-CAN] Header validation failed\r\n");
                        (void)can_send_status(hcan, OTA_CMD_ERROR, frame.seq, 4U);
                        return 0;
                    }
                    if (memcmp(header.encryption_key_id,
                               g_firmware_aes256_key_id,
                               OTA_ENCRYPTION_KEY_ID_SIZE) != 0) {
                        printf("[AES-GCM] Encryption key id mismatch\r\n");
                        (void)can_send_status(hcan, OTA_CMD_ERROR, frame.seq, 18U);
                        return 0;
                    }
                    printf("[OTA-CAN][FLOW] Header complete and CRC32 valid\r\n");
                    printf("[OTA-CAN][HEADER] version=%lu firmware=%lu "
                           "ciphertext=%lu signature=%lu\r\n",
                           header.firmware_version, header.firmware_size,
                           header.payload_size, header.signature_size);
                    printf("[OTA-CAN][HEADER] publisher=%.16s sig_alg=%lu "
                           "enc_alg=%lu\r\n",
                           header.publisher_id, header.signature_algorithm,
                           header.encryption_algorithm);
                    can_print_hex("[OTA-CAN][HEADER] publisher_key_id=",
                                  header.key_id, sizeof(header.key_id));
                    can_print_hex("[OTA-CAN][HEADER] encryption_key_id=",
                                  header.encryption_key_id,
                                  sizeof(header.encryption_key_id));
                    can_print_hex("[OTA-CAN][HEADER] nonce=",
                                  header.nonce, sizeof(header.nonce));
                    can_print_hex("[OTA-CAN][HEADER] authentication_tag=",
                                  header.authentication_tag,
                                  sizeof(header.authentication_tag));
                    can_print_hex("[OTA-CAN][HEADER] firmware_sha256=",
                                  header.firmware_hash,
                                  sizeof(header.firmware_hash));
                    printf("[OTA-CAN][FLOW] Phase 2: receive ML-DSA-65 "
                           "signature (%lu bytes)\r\n",
                           header.signature_size);
                }
                continue;
            }

            if (signature_received < header.signature_size) {
                uint32_t take = header.signature_size - signature_received;
                if (take > (frame.length - offset)) take = frame.length - offset;
                memcpy(&ota_can_signature_buffer[signature_received],
                       &frame.payload[offset], take);
                signature_received += take;
                offset += take;

                if (signature_received == header.signature_size) {
                    printf("[OTA-CAN][FLOW] Signature received: %lu/%lu bytes\r\n",
                           signature_received, header.signature_size);
                    printf("[SEC] Verify ML-DSA-65 publisher signature\r\n");
                    if (!ota_signature_verify(&header, ota_can_signature_buffer)) {
                        printf("[SEC] Publisher authentication FAILED\r\n");
                        (void)can_send_status(hcan, OTA_CMD_ERROR, frame.seq, 14U);
                        return 0;
                    }
                    printf("[SEC] Publisher authentication OK, elapsed=%lu ms\r\n",
                           (uint32_t)(HAL_GetTick() - update_start));

                    printf("[AES-GCM] Initialize decryption, AAD=%lu bytes\r\n",
                           (uint32_t)sizeof(aad_header));
                    memcpy(&aad_header, &header, sizeof(aad_header));
                    memset(aad_header.authentication_tag, 0,
                           sizeof(aad_header.authentication_tag));
                    aad_header.header_crc32 = 0U;
                    if (!ota_aes_gcm_decrypt_init(&gcm_ctx,
                                                  g_firmware_aes256_key,
                                                  header.nonce,
                                                  (const uint8_t *)&aad_header,
                                                  sizeof(aad_header))) {
                        (void)can_send_status(hcan, OTA_CMD_ERROR, frame.seq, 19U);
                        return 0;
                    }
                    printf("[FLASH] Erase APP_B: start=0x%08lX size=0x%08lX\r\n",
                           APP_B_START_ADDR, APP_B_IMAGE_SIZE);
                    if (flash_if_erase_app_b() != FLASH_IF_OK) {
                        (void)can_send_status(hcan, OTA_CMD_ERROR, frame.seq, 5U);
                        return 0;
                    }
                    printf("[FLASH] APP_B erase OK\r\n");
                    ota_sha256_init(&sha_ctx);
                    crypto_ready = 1U;
                    printf("[OTA-CAN][FLOW] Phase 3: receive/decrypt/write "
                           "ciphertext (%lu bytes)\r\n", header.payload_size);
                }
                continue;
            }

            if (crypto_ready != 0U) {
                uint32_t take = header.payload_size - payload_received;
                uint32_t plain_offset = 0U;
                if (take > (frame.length - offset)) take = frame.length - offset;
                ota_aes_gcm_decrypt_update(&gcm_ctx, &frame.payload[offset],
                                           plain, take);
                ota_sha256_update(&sha_ctx, plain, take);

                while (plain_offset < take) {
                    uint32_t copy_len = sizeof(flash_buffer) - flash_buffer_len;
                    if (copy_len > (take - plain_offset)) {
                        copy_len = take - plain_offset;
                    }
                    memcpy(&flash_buffer[flash_buffer_len],
                           &plain[plain_offset], copy_len);
                    flash_buffer_len += copy_len;
                    plain_offset += copy_len;

                    if (flash_buffer_len == sizeof(flash_buffer)) {
                        if (flash_if_write(APP_B_START_ADDR + flash_written,
                                           flash_buffer, flash_buffer_len,
                                           0U) != FLASH_IF_OK) {
                            (void)can_send_status(hcan, OTA_CMD_ERROR,
                                                  frame.seq, 8U);
                            return 0;
                        }
                        flash_written += flash_buffer_len;
                        flash_buffer_len = 0U;
                        if (flash_written >= next_flash_report) {
                            printf("[FLASH] APP_B written=%lu/%lu bytes, "
                                   "next=0x%08lX\r\n",
                                   flash_written, header.firmware_size,
                                   APP_B_START_ADDR + flash_written);
                            next_flash_report += OTA_CAN_DEBUG_FLASH_INTERVAL;
                        }
                    }
                }
                payload_received += take;
                offset += take;
            }
        }

        stream_received += frame.length;
        data_frames_received++;
        (void)can_send_status(hcan, OTA_CMD_ACK, frame.seq, stream_received);
        expected_seq++;

        if (((stream_received * 100U) / total_size) >= next_progress) {
            printf("[OTA-CAN][PROGRESS] %lu/%lu bytes (%lu%%), "
                   "frames=%lu last_seq=%u\r\n",
                   stream_received, total_size,
                   (stream_received * 100U) / total_size,
                   data_frames_received, frame.seq);
            while (next_progress <= ((stream_received * 100U) / total_size)) {
                next_progress += 10U;
            }
        }
    }

    if (!can_read_request(hcan, &frame, OTA_CAN_FRAME_TIMEOUT_MS) ||
        (frame.cmd != OTA_CMD_END) || (frame.seq != expected_seq) ||
        (frame.length != 0U)) {
        printf("[OTA-CAN] END failed\r\n");
        (void)can_send_status(hcan, OTA_CMD_ERROR, expected_seq, 9U);
        return 0;
    }
    can_log_request("accepted", &frame);
    printf("[OTA-CAN][FLOW] All DATA received: bytes=%lu frames=%lu; "
           "finalize image\r\n", stream_received, data_frames_received);

    if (flash_buffer_len != 0U) {
        if (flash_if_write(APP_B_START_ADDR + flash_written, flash_buffer,
                           flash_buffer_len, 1U) != FLASH_IF_OK) {
            (void)can_send_status(hcan, OTA_CMD_ERROR, frame.seq, 8U);
            return 0;
        }
        flash_written += flash_buffer_len;
        printf("[FLASH] Final write=%lu bytes, APP_B total=%lu/%lu\r\n",
               flash_buffer_len, flash_written, header.firmware_size);
    }

    ota_sha256_final(&sha_ctx, final_hash);
    can_print_hex("[SEC] Computed plaintext SHA-256=", final_hash,
                  sizeof(final_hash));
    can_print_hex("[SEC] Expected plaintext SHA-256=", header.firmware_hash,
                  sizeof(header.firmware_hash));
    printf("[AES-GCM] Verify authentication tag\r\n");
    if (!ota_aes_gcm_decrypt_final(&gcm_ctx, header.authentication_tag)) {
        printf("[AES-GCM] Authentication tag FAILED\r\n");
        (void)can_send_status(hcan, OTA_CMD_ERROR, frame.seq, 20U);
        return 0;
    }
    printf("[AES-GCM] Authentication tag OK\r\n");
    if (!ota_hash_equal(final_hash, header.firmware_hash)) {
        printf("[OTA-CAN] Plaintext SHA-256 failed\r\n");
        (void)can_send_status(hcan, OTA_CMD_ERROR, frame.seq, 10U);
        return 0;
    }
    printf("[SEC] Plaintext SHA-256 OK\r\n");

    printf("[SECURE BOOT] Write App B Manifest: addr=0x%08lX "
           "header=%lu signature=%lu\r\n",
           APP_B_MANIFEST_ADDR, (uint32_t)sizeof(header),
           header.signature_size);
    if ((flash_if_write(APP_B_MANIFEST_ADDR, (const uint8_t *)&header,
                        sizeof(header), 1U) != FLASH_IF_OK) ||
        (flash_if_write(APP_B_MANIFEST_ADDR + APP_MANIFEST_SIGNATURE_OFFSET,
                        ota_can_signature_buffer, header.signature_size,
                        1U) != FLASH_IF_OK)) {
        (void)can_send_status(hcan, OTA_CMD_ERROR, frame.seq, 15U);
        return 0;
    }
    printf("[SECURE BOOT] Manifest write OK; verify installed APP_B\r\n");
    if (!secure_boot_verify_app(APP_B_START_ADDR)) {
        (void)can_send_status(hcan, OTA_CMD_ERROR, frame.seq, 17U);
        return 0;
    }
    printf("[SECURE BOOT] Installed APP_B verification OK\r\n");

    printf("[BOOT] Update Metadata: active_slot=B pending_verify=1\r\n");
    ota_metadata_load_or_init(&meta);
    ota_metadata_prepare_app_b(&meta, header.firmware_size,
                               header.firmware_hash);
    if (!ota_metadata_save(&meta)) {
        (void)can_send_status(hcan, OTA_CMD_ERROR, frame.seq, 11U);
        return 0;
    }

    printf("[OTA-CAN][FLOW] OTA SUCCESS: version=%lu bytes=%lu frames=%lu "
           "elapsed=%lu ms\r\n",
           header.firmware_version, header.firmware_size,
           data_frames_received, (uint32_t)(HAL_GetTick() - update_start));
    printf("[OTA-CAN][TX] ACK END seq=%u value=0\r\n", frame.seq);
    printf("[OTA-CAN][FLOW] Reboot to App B in 200 ms\r\n");
    (void)can_send_status(hcan, OTA_CMD_ACK, frame.seq, 0U);
    HAL_Delay(200U);
    NVIC_SystemReset();
    return 1;
}

void ota_wait_for_update_can(CAN_HandleTypeDef *hcan)
{
    while (1) {
        if (ota_can_should_enter_update_mode(hcan)) {
            (void)ota_receive_update_can(hcan);
        }
        HAL_Delay(100U);
    }
}
