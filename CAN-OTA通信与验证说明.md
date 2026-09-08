# CAN OTA 通信与验证说明

## 1. 当前通信方式

当前 Bootloader 已从 UART OTA 切换为经典 CAN 2.0A OTA：

- CAN 外设：CAN1；
- 波特率：500 kbit/s；
- CAN_RX：PD0，AF9；
- CAN_TX：PD1，AF9；
- PC 到板：标准帧 ID `0x600`；
- 板到 PC：标准帧 ID `0x601`；
- LPUART1：只保留调试日志，不再传输 OTA 数据。

AES-256-GCM、ML-DSA-65、SHA-256、Secure Boot、Manifest、Metadata、APP_B 确认和 APP_A 回滚功能均保持不变。

## 2. 硬件连接

STM32 的 PD0/PD1 是 CAN 控制器逻辑信号，不能直接接 CANH/CANL，必须外接 3.3 V CAN 收发器，例如 SN65HVD230。

```text
STM32 PD1 (CAN1_TX)  -> 收发器 D/TXD
STM32 PD0 (CAN1_RX)  <- 收发器 R/RXD
STM32 3.3 V          -> 收发器 VCC
STM32 GND            -> 收发器 GND -> USB-CAN GND
收发器 CANH          -> USB-CAN CANH
收发器 CANL          -> USB-CAN CANL
```

CAN 总线两端各使用一个 120 Ω 终端电阻。只有板子和 USB-CAN 两个节点时，这两个节点就是总线两端。不要用只支持 5 V 逻辑输出的收发器直接驱动 STM32 RX。

## 3. CAN 帧格式

### 3.1 PC 到 Bootloader，ID 0x600

```text
Byte 0      命令
Byte 1..2   16-bit little-endian sequence
Byte 3      payload length，0..4
Byte 4..7   最多 4 字节 payload
```

命令：

- `0x01 START`：payload 为 OTA 总长度，4 字节小端；
- `0x02 DATA`：连续 OTA 字节流，每帧最多 4 字节；
- `0x03 END`：payload 为空。

### 3.2 Bootloader 到 PC，ID 0x601

```text
Byte 0      0x79 ACK 或 0x1F ERROR
Byte 1..2   对应 sequence
Byte 3..6   32-bit little-endian code
```

DATA ACK 的 code 是 MCU 已接收的累计 OTA 字节数；END ACK 的 code 为 0。每个 DATA 帧收到 ACK 后 PC 才发送下一帧，用于检测丢帧、乱序和 MCU 处理错误。

## 4. MCU 接收流程

`firmware.ota` 被当作连续字节流：

```text
148-byte Header
  -> 3309-byte ML-DSA-65 signature
  -> AES-GCM ciphertext
```

Bootloader 不在 RAM 保存完整 OTA：

1. 组装并校验 148 字节 Header；
2. 缓存 3309 字节签名并认证发布者；
3. 验签成功后才擦除 APP_B；
4. 密文边接收边 AES-GCM 解密；
5. 明文使用 256 字节缓冲写 Flash；
6. END 后验证 GCM tag 和明文 SHA-256；
7. 写 APP_B Manifest；
8. 立即 Secure Boot 验证 APP_B；
9. 修改 Metadata、复位并试运行 APP_B。

关键代码：

- `bootloader/Core/Src/ota_transport_can.c`；
- `bootloader/Core/Src/main.c` 中的 `MX_CAN1_Init()`；
- `bootloader/Core/Src/stm32l4xx_hal_msp.c` 中的 CAN GPIO；
- `pc_tool/send_can.py`；
- `pc_tool/can_protocol.py`。

## 5. PC 环境准备

```powershell
cd C:\Users\3nigma\Desktop\armPrj\μPQC-OTA_1\pc_tool
python -m pip install -r .\requirements.txt
```

USB-CAN 适配器还需要安装厂商驱动。

## 6. 发送 firmware.ota

### 6.1 PCAN-USB

```powershell
python .\send_can.py `
  --interface pcan `
  --channel PCAN_USBBUS1 `
  --bitrate 500000 `
  --file .\firmware.ota
```

### 6.2 SLCAN 适配器

```powershell
python .\send_can.py `
  --interface slcan `
  --channel COM5 `
  --bitrate 500000 `
  --file .\firmware.ota
```

命令启动后按板子 RESET。PC 会快速重复 START，以命中 Bootloader 的 1 秒入口窗口。

成功时 PC 显示：

```text
[CAN] START acknowledged, total=9433
[CAN] [##############################] 9433/9433 bytes 100.0%
[CAN] OTA SUCCESS, firmware version=3
```

UART 调试口应显示：

```text
[OTA-CAN] Enter update mode, total=9433
[OTA-CAN] Header OK, version=3 size=5976
[SEC] Publisher authentication OK
[AES-GCM] Authentication tag OK
[SECURE BOOT] Write App B Manifest
[SECURE BOOT] PASS ...
[OTA-CAN] OTA SUCCESS
[OTA-CAN] Reboot to App B
```

## 7. 测试命令

无需硬件的协议和虚拟总线测试：

```powershell
python .\test_can_protocol.py
python .\test_can_transport_virtual.py
```

完整安全回归：

```powershell
python .\verify_ota.py --file .\firmware.ota
python .\test_signed_ota.py
python .\test_secure_boot.py
```

## 8. 常见问题

### START 超时

依次检查：

1. 新 CAN Bootloader 是否已烧录；
2. 执行发送命令后是否按 RESET；
3. 双方是否都是 500 kbit/s；
4. CANH、CANL 和 GND 是否连接正确；
5. 是否有两个 120 Ω 终端；
6. 收发器 STB/RS 引脚是否处于正常工作模式；
7. `--interface` 和 `--channel` 是否匹配适配器型号。

### PC 有发送但没有 ACK

检查 PD1 是否连接收发器 TXD、PD0 是否连接 RXD，不能接反。总线上还必须有另一个正常节点提供 CAN 硬件 ACK。

### 能升级但看不到日志

CAN 只传输 OTA 协议，不发送文本日志。文本仍从 LPUART1 115200-8-N-1 输出，需要另外打开 COM3 查看。

## 9. CubeMX 注意事项

当前 Bootloader 的 CAN 和 LPUART 初始化由工程源码手工维护，原始 `bootloader.ioc` 没有完整反映这些自定义设置。不要直接用 CubeMX 无审核地重新生成代码，否则可能覆盖 `main.c` 和 MSP 中的 CAN 配置。
