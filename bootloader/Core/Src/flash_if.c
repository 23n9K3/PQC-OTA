#include "flash_if.h"
#include "ota_config.h"

#include "stm32l4xx_hal.h"
#include <stdio.h>
#include <string.h>

#ifndef FLASH_PAGE_SIZE
#define FLASH_PAGE_SIZE 0x1000U
#endif

static uint32_t flash_page_from_addr(uint32_t address)
{
#ifdef FLASH_BANK_2
    if (address >= (FLASH_BASE_ADDR + 0x00100000U)) {
        return (address - (FLASH_BASE_ADDR + 0x00100000U)) / FLASH_PAGE_SIZE;
    }
#endif
    return (address - FLASH_BASE_ADDR) / FLASH_PAGE_SIZE;
}

static uint32_t flash_bank_from_addr(uint32_t address)
{
#ifdef FLASH_BANK_2
    if (address >= (FLASH_BASE_ADDR + 0x00100000U)) {
        return FLASH_BANK_2;
    }
#endif
    return FLASH_BANK_1;
}

int flash_if_is_writable_range(uint32_t address, uint32_t length)
{
    uint32_t end;

    if (length == 0U) {
        return 1;
    }

    end = address + length;
    if (end < address) {
        return 0;
    }

    /* 只允许写 App B 和 Metadata，避免误擦 Bootloader / App A。 */
    if ((address >= APP_B_START_ADDR) && (end <= (APP_B_START_ADDR + APP_B_SIZE))) {
        return 1;
    }

    if ((address >= OTA_METADATA_ADDR) && (end <= (OTA_METADATA_ADDR + OTA_METADATA_SIZE))) {
        return 1;
    }

    printf("[FLASH] Address out of range: 0x%08lX len=%lu\r\n", address, length);
    return 0;
}

static flash_if_status_t flash_if_erase_range(uint32_t start, uint32_t length)
{
    FLASH_EraseInitTypeDef erase_init;
    uint32_t page_error = 0U;
    HAL_StatusTypeDef status;
    uint32_t first_page = flash_page_from_addr(start);
    uint32_t page_count = (length + FLASH_PAGE_SIZE - 1U) / FLASH_PAGE_SIZE;

    if (!flash_if_is_writable_range(start, length)) {
        return FLASH_IF_ERROR;
    }

    HAL_FLASH_Unlock();
		__HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_ALL_ERRORS);

    memset(&erase_init, 0, sizeof(erase_init));
    erase_init.TypeErase = FLASH_TYPEERASE_PAGES;
    erase_init.Banks = flash_bank_from_addr(start);
    erase_init.Page = first_page;
    erase_init.NbPages = page_count;

    status = HAL_FLASHEx_Erase(&erase_init, &page_error);
    HAL_FLASH_Lock();

    if (status != HAL_OK) {
        printf("[FLASH] Erase failed, page=%lu error=0x%08lX\r\n", page_error, HAL_FLASH_GetError());
        return FLASH_IF_ERROR;
    }

    return FLASH_IF_OK;
}

flash_if_status_t flash_if_erase_app_b(void)
{
    printf("[FLASH] Erase App B\r\n");
    return flash_if_erase_range(APP_B_START_ADDR, APP_B_SIZE);
}

flash_if_status_t flash_if_erase_metadata(void)
{
    printf("[FLASH] Erase Metadata\r\n");
    return flash_if_erase_range(OTA_METADATA_ADDR, OTA_METADATA_SIZE);
}

flash_if_status_t flash_if_write(uint32_t address, const uint8_t *data, uint32_t length, uint8_t pad_final)
{
    uint32_t offset = 0U;
    uint32_t checked_length = length;
    uint8_t word_buf[8];

    if ((pad_final != 0U) && ((length & 0x7U) != 0U)) {
        checked_length = (length + 7U) & ~0x7U;
    }

    if (!flash_if_is_writable_range(address, checked_length)) {
        return FLASH_IF_ERROR;
    }

    HAL_FLASH_Unlock();

    while (offset < length) {
        uint32_t copy_len = length - offset;
        uint64_t double_word = 0xFFFFFFFFFFFFFFFFULL;

        if (copy_len > 8U) {
            copy_len = 8U;
        }

        if ((copy_len < 8U) && (pad_final == 0U)) {
            printf("[FLASH] Program length is not 8-byte aligned\r\n");
            HAL_FLASH_Lock();
            return FLASH_IF_ERROR;
        }

        memset(word_buf, 0xFF, sizeof(word_buf));
        memcpy(word_buf, &data[offset], copy_len);
        memcpy(&double_word, word_buf, sizeof(double_word));

        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, address + offset, double_word) != HAL_OK) {
            printf("[FLASH] Program failed at 0x%08lX error=0x%08lX\r\n", address + offset, HAL_FLASH_GetError());
            HAL_FLASH_Lock();
            return FLASH_IF_ERROR;
        }

        if (memcmp((const void *)(address + offset), word_buf, sizeof(word_buf)) != 0) {
            printf("[FLASH] Verify failed at 0x%08lX\r\n", address + offset);
            HAL_FLASH_Lock();
            return FLASH_IF_ERROR;
        }

        offset += copy_len;
    }

    HAL_FLASH_Lock();
    return FLASH_IF_OK;
}
