#ifndef OTA_TRANSPORT_UART_H
#define OTA_TRANSPORT_UART_H

#include "stm32l4xx_hal.h"

int ota_receive_update_uart(UART_HandleTypeDef *huart);
int ota_should_enter_update_mode(UART_HandleTypeDef *huart);
void ota_wait_for_update(UART_HandleTypeDef *huart);

#endif
