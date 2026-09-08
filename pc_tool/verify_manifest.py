#!/usr/bin/env python3
"""Verify a persistent Secure Boot Manifest against an application binary."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import tempfile
from pathlib import Path

from ota_format import key_id_from_public_key, parse_app_manifest, validate_header


SCRIPT_DIR = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description="验证APP Secure Boot Manifest")
    parser.add_argument("--manifest", required=True, help="4096字节Manifest文件")
    parser.add_argument("--app", required=True, help="对应的APP bin文件")
    parser.add_argument("--public-key", default=str(SCRIPT_DIR / "keys" / "dev_publisher_pk.bin"))
    parser.add_argument("--mldsa-tool", default=str(SCRIPT_DIR / "mldsa_tool.exe"))
    args = parser.parse_args()

    app = Path(args.app).read_bytes()
    public_key = Path(args.public_key).read_bytes()
    header, header_raw, signature = parse_app_manifest(Path(args.manifest).read_bytes())
    validate_header(header_raw)
    if len(app) != header.firmware_size or hashlib.sha256(app).digest() != header.firmware_hash:
        raise SystemExit("[MANIFEST] FAILED: App长度或SHA-256与Manifest不匹配")
    if key_id_from_public_key(public_key) != header.key_id:
        raise SystemExit("[MANIFEST] FAILED: Key ID与公钥不匹配")

    with tempfile.TemporaryDirectory(prefix="upqc_manifest_") as directory:
        header_path = Path(directory) / "header.bin"
        signature_path = Path(directory) / "signature.bin"
        header_path.write_bytes(header_raw)
        signature_path.write_bytes(signature)
        result = subprocess.run(
            [args.mldsa_tool, "verify", args.public_key, str(header_path), str(signature_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise SystemExit("[MANIFEST] FAILED: ML-DSA-65签名无效")

    publisher = header.publisher_id.rstrip(b"\0").decode("ascii", errors="replace")
    print("[MANIFEST] PASS")
    print(f"[MANIFEST] publisher : {publisher}")
    print(f"[MANIFEST] version   : {header.firmware_version}")
    print(f"[MANIFEST] app size  : {len(app)} bytes")
    print("[MANIFEST] hash and ML-DSA-65 signature valid")


if __name__ == "__main__":
    main()
