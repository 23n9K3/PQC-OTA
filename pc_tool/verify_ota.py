#!/usr/bin/env python3
"""Verify ML-DSA publisher signature and AES-256-GCM OTA ciphertext."""

from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path

from ota_format import decrypt_payload, key_id_from_public_key, parse_ota

SCRIPT_DIR = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description="离线验证并解密firmware.ota")
    parser.add_argument("--file", required=True)
    parser.add_argument("--public-key", default=str(SCRIPT_DIR / "keys" / "dev_publisher_pk.bin"))
    parser.add_argument("--aes-key", default=str(SCRIPT_DIR / "keys" / "dev_firmware_aes256_key.bin"))
    parser.add_argument("--mldsa-tool", default=str(SCRIPT_DIR / "mldsa_tool.exe"))
    parser.add_argument("--extract", help="可选：输出验证后的明文App")
    args = parser.parse_args()

    public_key = Path(args.public_key).read_bytes()
    aes_key = Path(args.aes_key).read_bytes()
    header, header_raw, signature, ciphertext = parse_ota(Path(args.file).read_bytes())
    if key_id_from_public_key(public_key) != header.key_id:
        raise SystemExit("[VERIFY] FAILED: OTA key_id与指定公钥不匹配")
    with tempfile.TemporaryDirectory(prefix="upqc_verify_") as directory:
        header_path = Path(directory) / "signed_header.bin"
        signature_path = Path(directory) / "header.sig"
        header_path.write_bytes(header_raw)
        signature_path.write_bytes(signature)
        result = subprocess.run(
            [args.mldsa_tool, "verify", args.public_key, str(header_path), str(signature_path)],
            capture_output=True, text=True)
        if result.returncode != 0:
            raise SystemExit("[VERIFY] FAILED: ML-DSA-65签名无效")
    try:
        plaintext = decrypt_payload(header, ciphertext, aes_key)
    except Exception as exc:
        raise SystemExit(f"[VERIFY] FAILED: AES-256-GCM认证解密失败: {exc}") from exc
    if args.extract:
        Path(args.extract).write_bytes(plaintext)
    publisher = header.publisher_id.rstrip(b"\0").decode("ascii", errors="replace")
    print("[VERIFY] PASS")
    print(f"[VERIFY] publisher : {publisher}")
    print(f"[VERIFY] sign key  : {header.key_id.hex()}")
    print(f"[VERIFY] AES key   : {header.encryption_key_id.hex()}")
    print(f"[VERIFY] version   : {header.firmware_version}")
    print(f"[VERIFY] ciphertext: {len(ciphertext)} bytes")
    print(f"[VERIFY] plaintext : {len(plaintext)} bytes, SHA-256 matched")
    print("[VERIFY] AES-GCM   : tag valid")
    print("[VERIFY] signature : ML-DSA-65 valid")


if __name__ == "__main__":
    main()
