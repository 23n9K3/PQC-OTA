#!/usr/bin/env python3
"""Generate one development AES-256 key and its Bootloader C source."""

import argparse
import hashlib
import secrets
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
DEFAULT_KEY = SCRIPT_DIR / "keys" / "dev_firmware_aes256_key.bin"
DEFAULT_C = ROOT / "bootloader" / "Core" / "Src" / "firmware_decryption_key.c"


def c_array(data: bytes) -> str:
    return ",\n".join("    " + ", ".join(f"0x{x:02X}U" for x in data[i:i + 12])
                       for i in range(0, len(data), 12))


def main() -> None:
    parser = argparse.ArgumentParser(description="生成开发AES-256固件解密密钥")
    parser.add_argument("--key-output", default=str(DEFAULT_KEY))
    parser.add_argument("--c-output", default=str(DEFAULT_C))
    parser.add_argument("--force", action="store_true", help="覆盖已有密钥，会使旧OTA不可解密")
    args = parser.parse_args()
    key_path, c_path = Path(args.key_output), Path(args.c_output)
    if key_path.exists() and not args.force:
        key = key_path.read_bytes()
        if len(key) != 32:
            raise SystemExit("已有AES密钥不是32字节；确认后使用--force重建")
    else:
        key = secrets.token_bytes(32)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(key)
    key_id = hashlib.sha256(key).digest()[:16]
    source = f'''#include "firmware_decryption_key.h"\n\n/* DEVELOPMENT KEY ONLY. Replace with protected product/device provisioning. */\nconst uint8_t g_firmware_aes256_key[FIRMWARE_AES256_KEY_SIZE] = {{\n{c_array(key)}\n}};\n\nconst uint8_t g_firmware_aes256_key_id[FIRMWARE_AES_KEY_ID_SIZE] = {{\n{c_array(key_id)}\n}};\n'''
    c_path.parent.mkdir(parents=True, exist_ok=True)
    c_path.write_text(source, encoding="ascii", newline="\n")
    print(f"[AES KEY] key file : {key_path}")
    print(f"[AES KEY] C source : {c_path}")
    print(f"[AES KEY] key_id   : {key_id.hex()}")
    print("[AES KEY] WARNING  : development key; replace storage for production")


if __name__ == "__main__":
    main()
