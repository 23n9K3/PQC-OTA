#ifndef OTA_TRANSPORT_CAN_H
#define OTA_TRANSPORT_CAN_H

#include "stm32l4xx_hal.h"

#define OTA_CAN_REQUEST_ID 0x600U
#define OTA_CAN_STATUS_ID  0x601U
#define OTA_CAN_DATA_BYTES 4U

/* Wait for a CAN START frame during the Bootloader entry window. */
int ota_can_should_enter_update_mode(CAN_HandleTypeDef *hcan);

/* Consume the pending START and install one complete encrypted/signed OTA. */
int ota_receive_update_can(CAN_HandleTypeDef *hcan);

/* Wait forever for a new CAN OTA after no authenticated application remains. */
void ota_wait_for_update_can(CAN_HandleTypeDef *hcan);

#endif
