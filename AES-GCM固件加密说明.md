# AES-GCM 固件加密说明

## 1. 新增功能

当前工程的 OTA 格式已升级为 v3，并新增 AES-256-GCM 固件加密：

- **机密性**：串口上传输的是密文，不能直接从 `firmware.ota` 取得 APP 机器码。
- **密文完整性与认证**：修改密文、nonce、AAD 或 GCM tag 都会导致认证失败。
- **发布者认证**：ML-DSA-65 对最终 Header 签名，攻击者无法替换 AES 参数、版本、摘要或 tag。
- **安装后完整性**：解密明文还会校验 SHA-256；以后每次启动继续由 Secure Boot 验签并检查 Flash 中 APP 的 SHA-256。

AES-GCM 不替代 ML-DSA。AES 密钥证明发送方知道共享密钥，ML-DSA 签名证明固件来自受信任发布者。

## 2. OTA v3 文件结构

```text
[148-byte signed Header]
[3309-byte ML-DSA-65 signature]
[AES-256-GCM ciphertext，长度等于明文 APP]
```

Header 新增：`encryption_algorithm`、16 字节 AES Key ID、12 字节随机 nonce 和 16 字节 GCM tag。

GCM AAD 是 148 字节 Header 的规范副本，其中 `authentication_tag` 和 `header_crc32` 清零。生成 tag 后写回最终 Header、计算 CRC32，再用 ML-DSA-65 签名最终 Header。

## 3. 打包流程

```text
APP 明文 bin
  -> SHA-256
  -> 生成随机 12-byte nonce
  -> AES-256-GCM(明文, Header AAD)
  -> 得到等长密文和 16-byte tag
  -> 生成最终 Header 和 CRC32
  -> ML-DSA-65 签名最终 Header
  -> firmware.ota
```

每次 `pack.py` 都生成新 nonce。同一 AES 密钥绝不能复用 nonce；生产发布系统应使用持久化计数器或数据库保证全局唯一，随机 nonce 仅用于当前开发演示。

## 4. Bootloader 安装流程

1. 接收并检查 OTA v3 Header、长度和 CRC32。
2. 核对发布者 Key ID、AES Key ID 和算法编号。
3. 接收并验证 ML-DSA-65 签名。
4. 验签成功后才擦除 APP_B。
5. 初始化 AES-256-GCM；每收到一帧密文，流式认证并原地解密。
6. 把明文写入 APP_B，同时计算明文 SHA-256。
7. 收完后验证 GCM tag；失败则不写 Manifest/Metadata，残留明文不可启动。
8. 验证明文 SHA-256。
9. 把签名 Header 和签名写入 `0x081DF000` 的 APP_B Manifest。
10. 立即运行 Secure Boot 验证，通过后更新 Metadata 并复位启动 APP_B。

STM32L4R5ZI 没有 AES 外设实例，所以本工程使用软件 AES-256-GCM 流式实现；不需要在 RAM 保存整包密文。

## 5. 关键代码

- PC 格式/AAD：`pc_tool/ota_format.py`
- PC 加密打包：`pc_tool/pack.py`
- PC 离线验签/解密：`pc_tool/verify_ota.py`
- 开发 AES 密钥配置：`pc_tool/provision_dev_aes_key.py`
- MCU AES/GCM：`bootloader/Core/Src/ota_aes_gcm.c`
- MCU 开发密钥：`bootloader/Core/Src/firmware_decryption_key.c`
- UART 解密安装：`bootloader/Core/Src/ota_transport_uart.c`
- OTA v3 Header：`bootloader/Core/Inc/ota_protocol.h`

## 6. 安全边界

当前密钥源文件是开发方案，不是量产级安全存储。若攻击者可读取 Bootloader Flash，就可能得到 AES 密钥。量产至少应评估 STM32 RDP/WRP/PCROP、设备唯一密钥或安全芯片、调试口关闭、发布系统隔离，以及密钥轮换与 nonce 唯一性审计。
