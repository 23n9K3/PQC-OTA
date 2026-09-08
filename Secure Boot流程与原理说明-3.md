# Secure Boot 流程与原理说明

## 1. 文档目的

本文档说明当前 `μPQC-OTA_1` 工程中 Secure Boot 的工作原理、Flash 布局、信任链、APP_A/APP_B 启动流程、OTA 安装后的 Manifest 保存方式、失败回退策略和验证步骤。

当前 Secure Boot 使用：

- ML-DSA-65 后量子数字签名；
- SHA-256 APP 镜像完整性检查；
- Bootloader 内置受信任发布者 ID、Key ID 和 ML-DSA-65 公钥；
- APP_A/APP_B 独立持久 Manifest；
- Metadata 启动选择、APP_B 待确认启动和失败回滚。

## 2. Secure Boot 要解决的问题

仅检查 APP 向量表只能确认 MSP 和 Reset Handler 形式上合法，不能证明 APP 来自受信任发布者，也不能发现安装后的 Flash 内容被修改。

Secure Boot 在每次跳转 APP 前回答三个问题：

1. 这个 APP 是否由受信任发布者授权？
2. 这个 APP 自签名后是否发生过任何字节变化？
3. 这个 APP 的向量表和跳转地址是否合法？

只有三类检查全部通过，Bootloader 才跳转 APP。

## 3. 信任根和密钥原理

### 3.1 发布者私钥

ML-DSA-65 私钥只保存在 PC 发布环境、离线签名机或 HSM 中，用于给 APP 的签名 Header 生成数字签名。

开发测试私钥位于：

```text
pc_tool/keys/dev_publisher_sk.bin
```

该私钥只用于本地联调，不能用于量产，不能烧录到设备。

### 3.2 Bootloader 信任根

Bootloader 只内置：

- 16 字节 `publisher_id`；
- 16 字节 `key_id`；
- 1952 字节 ML-DSA-65 公钥。

信任根定义于：

```text
bootloader/Core/Src/trusted_publisher_key.c
```

Key ID 计算方式：

```text
key_id = SHA-256(public_key)[0:16]
```

Bootloader 使用公钥只能验证签名，无法生成新签名。

### 3.3 信任链

```text
发布者私钥
      |
      +-- 对APP签名Header生成ML-DSA-65签名
                         |
                         v
                 APP Secure Boot Manifest
                         |
                         v
Bootloader内置发布者ID + Key ID + 公钥
                         |
                         +-- 验签通过
                                  |
                                  +-- 校验APP SHA-256
                                           |
                                           +-- 检查向量表
                                                    |
                                                    +-- 跳转APP
```

## 4. Flash 分区和 Manifest

### 4.1 Flash 布局

```text
0x08000000  +----------------------------------+
            | Bootloader                       | 0x20000
0x08020000  +----------------------------------+
            | APP_A executable image           | 0xDF000
0x080FF000  +----------------------------------+
            | APP_A Secure Boot Manifest       | 0x1000
0x08100000  +----------------------------------+
            | APP_B executable image           | 0xDF000
0x081DF000  +----------------------------------+
            | APP_B Secure Boot Manifest       | 0x1000
0x081E0000  +----------------------------------+
            | OTA Metadata                     | 0x20000
0x08200000  +----------------------------------+
```

APP_A 和 APP_B 的 Keil IROM1 大小必须是 `0x000DF000`，不能再使用 `0x000E0000`，否则 APP 链接器可能将代码或常量放入 Manifest 页。

### 4.2 Manifest 页结构

```text
页内偏移 0                      100       104                  3413       4096
          +-----------------------+---------+----------------------+----------+
          | Signed Header (100B)  | FF pad  | ML-DSA signature     | FF pad   |
          |                       | 4 bytes | 3309 bytes           |          |
          +-----------------------+---------+----------------------+----------+
```

签名从偏移 104 开始，用于满足 STM32L4 Flash 双字 8 字节编程对齐要求。

### 4.3 签名 Header

100 字节 Header 包含：

| 字段 | 作用 |
| --- | --- |
| magic / header_version | 识别 OTA v2 和 Manifest 格式 |
| firmware_version | APP 发布版本 |
| firmware_size / payload_size | 参与 hash 的 APP 长度 |
| firmware_hash | APP 可执行镜像的 SHA-256 |
| publisher_id | 发布者身份 |
| key_id | 发布公钥指纹 |
| signature_algorithm | ML-DSA-65 算法 ID |
| signature_size | 签名长度 3309 |
| header_crc32 | Header 传输损坏快速检查 |

ML-DSA-65 对完整 Header 签名，并使用固定上下文：

```text
UPQC-OTA-SIGN-V2
```

因为 Header 中包含 APP SHA-256，所以签名同时绑定了发布者、密钥、版本、镜像长度和完整 APP 内容。

## 5. 每次启动的 Secure Boot 流程

### 5.1 总体流程

```text
复位
  |
  v
Bootloader启动并读取Metadata
  |
  +-- 1秒OTA入口窗口
  |
  v
Metadata选择APP_A或APP_B
  |
  v
读取对应Manifest
  |
  v
检查Header格式和长度
  |
  v
比较publisher_id和key_id
  |
  v
使用内置公钥验证ML-DSA-65签名
  |
  v
计算Flash中APP的SHA-256
  |
  v
比较已签名firmware_hash
  |
  v
检查MSP和Reset Handler
  |
  v
设置VTOR、MSP并跳转APP
```

### 5.2 Manifest 格式检查

Bootloader 先检查：

- Manifest 地址是否对应 APP_A 或 APP_B；
- OTA magic 是否正确；
- Header version 是否为 2；
- APP 长度是否大于等于 8 字节；
- APP 长度是否不超过 `0xDF000`；
- 签名算法是否为 ML-DSA-65；
- 签名长度是否为 3309；
- Header CRC32 是否正确。

任何一项失败都不会进入 APP。

### 5.3 发布者和签名验证

Bootloader 用常数时间比较方式检查 Manifest 中的 `publisher_id` 和 `key_id`，然后调用：

```c
PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(...);
```

验签失败日志：

```text
[SECURE BOOT] Publisher signature invalid
```

这一步证明 Header 由持有受信任私钥的发布者制作，并且 Header 自签名后没有被修改。

### 5.4 APP 镜像 SHA-256 验证

验签通过后，Bootloader 根据 `firmware_size` 从 APP 起始地址读取实际 Flash 内容，计算 SHA-256：

```text
APP_A: SHA-256(0x08020000, firmware_size)
APP_B: SHA-256(0x08100000, firmware_size)
```

如果 APP 任意一个字节被改变，计算结果与已签名 Header 中的 `firmware_hash` 不同，日志为：

```text
[SECURE BOOT] App SHA-256 mismatch
```

### 5.5 向量表和跳转检查

签名和 hash 都通过后，Bootloader 继续检查：

- 向量表第 0 项的初始 MSP 是否位于合法 SRAM 范围；
- MSP 是否 8 字节对齐；
- 向量表第 1 项 Reset Handler 是否设置 Thumb bit；
- Reset Handler 是否位于当前 APP 可执行镜像范围。

最后 Bootloader 停止 SysTick，清除中断状态，设置 VTOR 和 MSP，然后跳转 APP Reset Handler。

正常日志：

```text
[BOOT] Try boot App B
[SECURE BOOT] Verify app at 0x08100000
[SECURE BOOT] PASS publisher=UPQC-PUBLISHER01 version=2 size=5976
[BOOT] Jump to app: 0x08100000
```

## 6. APP_B OTA 安装与 Manifest 持久化

### 6.1 OTA 包结构

```text
[100字节Signed Header][3309字节ML-DSA-65签名][APP_B Payload]
```

### 6.2 安装流程

```text
接收Header和签名
  |
先验证发布者和ML-DSA-65签名
  |
  +-- 失败：不擦除APP_B，返回ERROR 14
  |
  v
验签成功后擦除完整APP_B slot
  |
接收并写入APP_B Payload
  |
计算并比较Payload SHA-256
  |
将Header和签名写入APP_B Manifest页
  |
从Flash重新执行Secure Boot验证
  |
  +-- 失败：不更新Metadata
  |
  v
验证成功后更新Metadata
  |
重启并启动APP_B
```

APP_B Manifest 由 Bootloader 在 OTA 安装结束时自动写入 `0x081DF000`，不需要用户手工烧录。

关键日志：

```text
[SEC] Publisher authentication OK
[FLASH] Erase App B
[SECURE BOOT] Write App B Manifest
[SECURE BOOT] Verify app at 0x08100000
[SECURE BOOT] PASS ...
[OTA] OTA SUCCESS
[OTA] Reboot to App B
```

## 7. APP_A 初始 Manifest

APP_A 通常是用 Keil 或 STM32CubeProgrammer 直接烧录，不经过 OTA，所以 APP_A Manifest 需要在首次烧录时单独生成和烧录。

生成：

```powershell
cd C:\Users\3nigma\Desktop\armPrj\μPQC-OTA_1\pc_tool
& "D:\Keil\ARM\ARMCC\bin\fromelf.exe" --bin --output .\app_a.bin ..\app\MDK-ARM\APP_A\APP_A.axf
python .\pack.py --input .\app_a.bin --output .\app_a_signed.ota --manifest-output .\app_a_manifest.bin --version 1
python .\verify_manifest.py --manifest .\app_a_manifest.bin --app .\app_a.bin
```

烧录：

| 文件 | 地址 |
| --- | --- |
| `bootloader.hex` | HEX 自带 `0x08000000` |
| `APP_A.hex` | HEX 自带 `0x08020000` |
| `app_a_manifest.bin` | bin 手工指定 `0x080FF000` |

如果只烧录 APP_A 而没有烧录与该 APP_A 完全对应的 Manifest，Bootloader 会报告 Manifest 无效或 APP SHA-256 不匹配，并拒绝启动。

## 8. 失败回退原理

### 8.1 APP_B Secure Boot 失败

APP_B 在以下任意情况下被拒绝：

- Manifest 为空或格式错误；
- 发布者 ID 或 Key ID 不匹配；
- ML-DSA-65 签名无效；
- APP_B Flash SHA-256 不匹配；
- MSP 或 Reset Handler 不合法。

Bootloader 执行：

```text
将APP_B标记为无效
将active_slot设为APP_A
清除pending_verify和boot_count
保存Metadata
使用完全相同的Secure Boot流程验证APP_A
```

日志：

```text
[SECURE BOOT] App B rejected, fallback App A
```

### 8.2 APP_A 也失败

如果 APP_A 也无法通过 Manifest、签名、hash 或向量表检查，Bootloader 不跳转任何 APP，停留在 OTA 等待状态：

```text
[SECURE BOOT] No authenticated app, wait OTA
```

### 8.3 APP_B 运行确认失败

Secure Boot PASS 表示 APP_B 的身份和内容正确，但不代表应用业务一定能正常运行。APP_B 启动后还需要调用：

```c
app_confirm_boot_ok();
```

如 APP_B 连续启动后未在限定次数内确认，Metadata 回滚机制会选择 APP_A。这与数字签名失败是两种不同的回退原因。

## 9. 关键代码调用链

### 9.1 启动验签

```text
main.c
  -> ota_boot_selected_app()
      -> secure_boot_verify_app()
          -> ota_header_validate()
          -> ota_signature_verify()
              -> trusted_publisher_matches()
              -> PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx()
          -> ota_sha256_compute()
          -> ota_hash_equal()
      -> boot_jump_to_app()
```

### 9.2 OTA 安装

```text
ota_transport_uart.c
  -> 接收Header和签名
  -> ota_signature_verify()
  -> flash_if_erase_app_b()
  -> flash_if_write(APP_B Payload)
  -> 校验Payload SHA-256
  -> flash_if_write(APP_B Manifest)
  -> secure_boot_verify_app(APP_B_START_ADDR)
  -> ota_metadata_prepare_app_b()
  -> ota_metadata_save()
```

### 9.3 关键文件

| 文件 | 用途 |
| --- | --- |
| `bootloader/Core/Src/secure_boot.c` | 启动前 Manifest、签名和 APP hash 验证 |
| `bootloader/Core/Src/main.c` | 启动选择、APP_B 失败后回退 APP_A |
| `bootloader/Core/Src/ota_signature.c` | ML-DSA-65 验签业务入口 |
| `bootloader/Core/Src/trusted_publisher.c` | 发布者 ID 和 Key ID 匹配 |
| `bootloader/Core/Src/trusted_publisher_key.c` | Bootloader 内置信任根 |
| `bootloader/Core/Src/ota_transport_uart.c` | OTA 认证、APP_B 写入和 Manifest 持久化 |
| `bootloader/Core/Src/boot_jump.c` | APP 向量表检查和跳转 |
| `pc_tool/pack.py` | 生成签名 OTA 和 4 KB Manifest |
| `pc_tool/verify_manifest.py` | PC 端离线检查 Manifest |
| `pc_tool/test_secure_boot.py` | APP/Manifest 篡改回归测试 |

## 10. 验证步骤

### 10.1 PC 端回归验证

```powershell
cd C:\Users\3nigma\Desktop\armPrj\μPQC-OTA_1\pc_tool
python .\verify_manifest.py --manifest .\app_a_manifest.bin --app .\app_a.bin
python .\verify_manifest.py --manifest .\app_b_manifest.bin --app .\app_b.bin
python .\test_secure_boot.py
```

预期：

```text
[MANIFEST] PASS
[SECURE-BOOT TEST] PASS: valid app_a.bin accepted
[SECURE-BOOT TEST] PASS: valid app_b.bin accepted
[SECURE-BOOT TEST] PASS: tampered APP rejected
[SECURE-BOOT TEST] PASS: tampered Manifest rejected
[SECURE-BOOT TEST] PASS: mismatched image/Manifest rejected
```

### 10.2 APP_A 启动验证

1. 烧录 Bootloader。
2. 烧录 APP_A HEX。
3. 将 `app_a_manifest.bin` 烧录到 `0x080FF000`。
4. 使用 Sector Erase，不要 Full Chip Erase。
5. 复位，确认：

```text
[SECURE BOOT] Verify app at 0x08020000
[SECURE BOOT] PASS ...
[BOOT] Jump to app: 0x08020000
```

### 10.3 APP_B OTA 和重启验证

```powershell
python .\send_uart.py --port COM3 --baud 115200 --timeout 60 --file .\firmware.ota
```

OTA 完成后再手动复位一次。每次启动都应先出现：

```text
[SECURE BOOT] Verify app at 0x08100000
[SECURE BOOT] PASS ...
```

然后才出现：

```text
[BOOT] Jump to app: 0x08100000
```

### 10.4 APP 篡改测试

1. 先备份 APP_B 和 `0x081DF000` Manifest Page。
2. 将 APP_B 镜像中任意一个非向量表字节改变，保持 Manifest 不变。
3. 复位，预期 APP_B SHA-256 失败并回退 APP_A。
4. 恢复 APP_B 后，改动 Manifest 签名区任意一字节。
5. 复位，预期 ML-DSA-65 签名失败并回退 APP_A。

测试后应恢复原始 APP_B 和 Manifest，或重新执行一次正常签名 OTA。

## 11. 当前安全边界

已实现：

- OTA 安装前 ML-DSA-65 发布者认证；
- APP_A/APP_B 独立持久 Manifest；
- 每次跳转前重新验证 ML-DSA-65 签名；
- 每次跳转前重新计算 APP SHA-256；
- APP_B 验证失败后回退 APP_A；
- APP_A 也失败时停留 Bootloader；
- APP_B 待确认启动和超时回滚。

尚未实现：

- Bootloader 自身的数字签名或不可变信任链；
- WRP/PCROP/RDP 对 Bootloader 和内置公钥的硬件保护；
- 版本单调计数器和防降级；
- AES-GCM 固件加密；
- 密钥轮换和公钥撤销表；
- 多副本交易式 Metadata 和掉电续传。

生产设备应进一步使用 HSM/离线签名机保护私钥，并使用 STM32 Option Bytes 保护 Bootloader 和信任根。
