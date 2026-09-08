#include "boot_jump.h"

#include "ota_config.h"
#include "stm32l4xx_hal.h"

#include <stdio.h>

typedef void (*boot_app_entry_t)(void);

static int is_valid_stack(uint32_t stack)
{
    return (stack >= SRAM_BASE_ADDR) && (stack < SRAM_END_ADDR) && ((stack & 0x7U) == 0U);
}

static uint32_t app_slot_size(uint32_t app_addr)
{
    if (app_addr == APP_A_START_ADDR) {
        return APP_A_IMAGE_SIZE;
    }
    if (app_addr == APP_B_START_ADDR) {
        return APP_B_IMAGE_SIZE;
    }
    return 0U;
}

static int is_valid_reset_handler(uint32_t reset, uint32_t app_addr, uint32_t app_size)
{
    uint32_t reset_addr = reset & ~0x1U;

    return ((reset & 0x1U) == 1U) &&
           (reset_addr >= app_addr) &&
           (reset_addr < (app_addr + app_size));
}

int boot_is_valid_app(uint32_t app_addr)
{
    uint32_t app_size = app_slot_size(app_addr);
    uint32_t app_stack;
    uint32_t app_reset;

    if (app_size == 0U) {
        printf("[BOOT] Invalid app base: 0x%08lX\r\n", app_addr);
        return 0;
    }

    app_stack = *(volatile uint32_t *)app_addr;
    app_reset = *(volatile uint32_t *)(app_addr + 4U);

    if (!is_valid_stack(app_stack)) {
        printf("[BOOT] Invalid app stack at 0x%08lX: 0x%08lX\r\n", app_addr, app_stack);
        return 0;
    }

    if (!is_valid_reset_handler(app_reset, app_addr, app_size)) {
        printf("[BOOT] Invalid app reset handler at 0x%08lX: 0x%08lX\r\n", app_addr + 4U, app_reset);
        return 0;
    }

    return 1;
}

void boot_jump_to_app(uint32_t app_addr)
{
    uint32_t app_stack;
    uint32_t app_reset;
    boot_app_entry_t app_entry;

    if (!boot_is_valid_app(app_addr)) {
        return;
    }

    app_stack = *(volatile uint32_t *)app_addr;
    app_reset = *(volatile uint32_t *)(app_addr + 4U);
    app_entry = (boot_app_entry_t)app_reset;

    printf("[BOOT] Jump to app: 0x%08lX\r\n", app_addr);

    __disable_irq();

    /* 停止 SysTick，避免 Bootloader 的节拍中断带到 App。 */
    SysTick->CTRL = 0U;
    SysTick->LOAD = 0U;
    SysTick->VAL = 0U;

    HAL_DeInit();
    HAL_RCC_DeInit();

    for (uint32_t i = 0U; i < 8U; i++) {
        NVIC->ICER[i] = 0xFFFFFFFFU;
        NVIC->ICPR[i] = 0xFFFFFFFFU;
    }

    SCB->ICSR = SCB_ICSR_PENDSTCLR_Msk | SCB_ICSR_PENDSVCLR_Msk;

    /*
     * VTOR 告诉 CPU：中断向量表从 App 的链接地址开始取。
     * MSP 是 App 的主栈指针，必须切到 App 向量表第 0 项，否则 App 会继续用 Bootloader 的栈。
     */
    SCB->VTOR = app_addr;
    __set_CONTROL(0U);
    __set_MSP(app_stack);
    __DSB();
    __ISB();

    __enable_irq();
    app_entry();
}
