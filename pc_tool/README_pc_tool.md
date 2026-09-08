# PC 签名与 OTA 工具

## 文件用途

- `build_mldsa_tool.ps1`：用项目中的 `MLDSA_CLEAN_M4` 纯 C 核心构建 PC 签名程序。
- `provision_dev_publisher.py`：生成开发密钥，将发布者 ID、Key ID 和公钥写入 Bootloader。
- `provision_dev_aes_key.py`：生成开发 AES-256 密钥和 Bootloader 密钥源文件。
- `pack.py`：AES-256-GCM 加密固件，再对最终 Header 做 ML-DSA-65 签名。
- `verify_ota.py`：离线验签、认证解密并核对明文 SHA-256。
- `verify_manifest.py`：检查每次启动验签使用的 4 KB APP Manifest。
- `send_can.py`：通过经典 CAN 发送加密签名 OTA（当前传输方式）。
- `can_protocol.py`：CAN OTA 帧格式。
- `send_uart.py`：旧 UART 工具，当前 Bootloader 不再编译 UART OTA 接收端。
- `test_signed_ota.py`：检查合法包通过，Header、签名和 Payload 的单比特篡改均被拒绝。

## 首次开发环境准备

```powershell
cd C:\Users\3nigma\Desktop\armPrj\μPQC-OTA_1\pc_tool
powershell -ExecutionPolicy Bypass -File .\build_mldsa_tool.ps1
python .\provision_dev_publisher.py --force
python .\provision_dev_aes_key.py
```

两个 provision 脚本生成/改变密钥后都必须重新编译和烧录 Bootloader。不要在每次发布时使用 `--force`，否则旧 Bootloader 无法验证或解密新包。

> 开发签名私钥和 AES 密钥只用于联调。生产环境必须用离线签名机/HSM 管理签名私钥，并采用受保护的设备密钥配置；不能把通用 AES 密钥以普通源码形式用于量产。

## 生成 APP_B 和签名 OTA

```powershell
& "D:\Keil\ARM\ARMCC\bin\fromelf.exe" --bin --output .\app_b.bin ..\app\MDK-ARM\APP_B\APP_B.axf
python .\pack.py --input .\app_b.bin --output .\firmware.ota --manifest-output .\app_b_manifest.bin --version 3
python .\verify_ota.py --file .\firmware.ota
python .\verify_manifest.py --manifest .\app_b_manifest.bin --app .\app_b.bin
```

`firmware.ota` 格式：

```text
[148-byte OTA v3 Header][3309-byte ML-DSA-65 signature][AES-GCM ciphertext]
```

Header 包含明文 SHA-256、AES Key ID、每包随机 96-bit nonce 和 128-bit GCM tag。GCM AAD 是把 tag 和 CRC 清零后的完整 Header；ML-DSA-65 签名覆盖最终 Header，因此发布者、版本、长度、明文摘要、加密参数和 tag 都被绑定。

## CAN 发送

安装依赖：

```powershell
python -m pip install -r .\requirements.txt
```

PCAN-USB 示例：

```powershell
python .\send_can.py --interface pcan --channel PCAN_USBBUS1 --bitrate 500000 --file .\firmware.ota
```

SLCAN 示例：

```powershell
python .\send_can.py --interface slcan --channel COM5 --bitrate 500000 --file .\firmware.ota
```

执行命令后复位板子。PC 重复发送 START，命中 Bootloader 的 1 秒 CAN 入口窗口后自动传输。LPUART1/COM3 现在只用于查看调试日志。

OTA 成功后 Bootloader 会自动将 Header 和签名保存到 `0x081DF000` 的 APP_B Manifest 页。以后每次启动 APP_B 前都会重新验签并检查 Flash 中的 APP_B SHA-256。

APP_A 不通过 OTA 安装，首次烧录时需要单独生成并烧录 Manifest：

```powershell
& "D:\Keil\ARM\ARMCC\bin\fromelf.exe" --bin --output .\app_a.bin ..\app\MDK-ARM\APP_A\APP_A.axf
python .\pack.py --input .\app_a.bin --output .\app_a_signed.ota --manifest-output .\app_a_manifest.bin --version 1
python .\verify_manifest.py --manifest .\app_a_manifest.bin --app .\app_a.bin
```

`app_a_manifest.bin` 必须以 bin 方式烧录到 `0x080FF000`。

## 回归测试

```powershell
python .\test_signed_ota.py
python .\test_secure_boot.py
python .\test_can_protocol.py
python .\test_can_transport_virtual.py
```

预期结果是合法包 accepted，tampered header/signature/ciphertext 全部 rejected。
