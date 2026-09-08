#!/usr/bin/env python3
"""Encrypt with AES-256-GCM, then sign an OTA v3 package with ML-DSA-65."""

from __future__ import annotations

import argparse
import secrets
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ota_format import (
    ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SECRET_KEY_SIZE,
    ML_DSA_65_SIGNATURE_SIZE, OTA_AES_256_KEY_SIZE, build_header,
    build_app_manifest, decrypt_payload, encode_identity,
    encryption_key_id_from_key, gcm_aad, key_id_from_public_key,
    pack_header, parse_ota,
)

SCRIPT_DIR = Path(__file__).resolve().parent


def run_tool(tool: Path, *args: str) -> None:
    result = subprocess.run([str(tool), *args], text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "ML-DSA工具执行失败")


def main() -> None:
    parser = argparse.ArgumentParser(description="生成AES-256-GCM加密、ML-DSA-65签名的OTA")
    parser.add_argument("--input", required=True, help="输入App明文bin")
    parser.add_argument("--output", required=True, help="输出firmware.ota")
    parser.add_argument("--version", required=True, type=int, help="固件版本号")
    parser.add_argument("--manifest-output", help="可选：输出4096字节Secure Boot Manifest")
    parser.add_argument("--publisher", default="UPQC-PUBLISHER01")
    parser.add_argument("--public-key", default=str(SCRIPT_DIR / "keys" / "dev_publisher_pk.bin"))
    parser.add_argument("--secret-key", default=str(SCRIPT_DIR / "keys" / "dev_publisher_sk.bin"))
    parser.add_argument("--aes-key", default=str(SCRIPT_DIR / "keys" / "dev_firmware_aes256_key.bin"))
    parser.add_argument("--mldsa-tool", default=str(SCRIPT_DIR / "mldsa_tool.exe"))
    args = parser.parse_args()

    payload = Path(args.input).read_bytes()
    public_key = Path(args.public_key).read_bytes()
    secret_key = Path(args.secret_key).read_bytes()
    aes_key = Path(args.aes_key).read_bytes()
    tool = Path(args.mldsa_tool)
    if not payload:
        raise SystemExit("输入bin文件为空")
    if len(public_key) != ML_DSA_65_PUBLIC_KEY_SIZE:
        raise SystemExit("ML-DSA-65公钥必须是1952字节")
    if len(secret_key) != ML_DSA_65_SECRET_KEY_SIZE:
        raise SystemExit("ML-DSA-65私钥必须是4032字节")
    if len(aes_key) != OTA_AES_256_KEY_SIZE:
        raise SystemExit("AES-256密钥必须是32字节，请先运行provision_dev_aes_key.py")
    if not tool.exists():
        raise SystemExit("缺少mldsa_tool.exe，请先运行build_mldsa_tool.ps1")

    publisher_id = encode_identity(args.publisher, 16, "publisher")
    signing_key_id = key_id_from_public_key(public_key)
    aes_key_id = encryption_key_id_from_key(aes_key)
    nonce = secrets.token_bytes(12)
    header = build_header(payload, args.version, publisher_id, signing_key_id,
                          aes_key_id, nonce)
    encrypted = AESGCM(aes_key).encrypt(nonce, payload, gcm_aad(header))
    ciphertext, header.authentication_tag = encrypted[:-16], encrypted[-16:]
    header_raw = pack_header(header)

    with tempfile.TemporaryDirectory(prefix="upqc_ota_") as directory:
        header_path = Path(directory) / "signed_header.bin"
        signature_path = Path(directory) / "header.sig"
        header_path.write_bytes(header_raw)
        run_tool(tool, "sign", str(args.secret_key), str(header_path), str(signature_path))
        run_tool(tool, "verify", str(args.public_key), str(header_path), str(signature_path))
        signature = signature_path.read_bytes()
    if len(signature) != ML_DSA_65_SIGNATURE_SIZE:
        raise SystemExit("ML-DSA-65签名长度错误")

    ota = header_raw + signature + ciphertext
    parsed_header, _, _, parsed_ciphertext = parse_ota(ota)
    if decrypt_payload(parsed_header, parsed_ciphertext, aes_key) != payload:
        raise SystemExit("AES-GCM打包后自检失败")
    Path(args.output).write_bytes(ota)
    if args.manifest_output:
        Path(args.manifest_output).write_bytes(build_app_manifest(header_raw, signature))

    print(f"[PACK] input       : {args.input}")
    print(f"[PACK] output      : {args.output}")
    print(f"[PACK] publisher   : {args.publisher}")
    print(f"[PACK] sign key_id : {signing_key_id.hex()}")
    print(f"[PACK] AES key_id  : {aes_key_id.hex()}")
    print(f"[PACK] nonce       : {nonce.hex()}")
    print(f"[PACK] GCM tag     : {header.authentication_tag.hex()}")
    print(f"[PACK] app size    : {len(payload)} bytes")
    print(f"[PACK] signature   : {len(signature)} bytes (ML-DSA-65)")
    print(f"[PACK] ota size    : {len(ota)} bytes")
    if args.manifest_output:
        print(f"[PACK] manifest    : {args.manifest_output} (4096 bytes)")
    print("[PACK] AES-256-GCM encryption and ML-DSA-65 signature verified")


if __name__ == "__main__":
    main()
