#!/usr/bin/env python3
"""Regression test: valid OTA passes and one-bit tampering is rejected."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from ota_format import OTA_HEADER_SIZE, ML_DSA_65_SIGNATURE_SIZE


SCRIPT_DIR = Path(__file__).resolve().parent


def verify(path: Path) -> int:
    return subprocess.run(
        [sys.executable, str(SCRIPT_DIR / "verify_ota.py"), "--file", str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode


def main() -> None:
    source_path = SCRIPT_DIR / "firmware.ota"
    source = source_path.read_bytes()
    if verify(source_path) != 0:
        raise SystemExit("[TEST] FAIL: valid OTA was rejected")
    print("[TEST] PASS: valid encrypted and signed OTA accepted")

    cases = {
        "header": 8,
        "signature": OTA_HEADER_SIZE,
        "ciphertext": OTA_HEADER_SIZE + ML_DSA_65_SIGNATURE_SIZE,
    }
    with tempfile.TemporaryDirectory(prefix="upqc_tamper_") as directory:
        for name, offset in cases.items():
            tampered = bytearray(source)
            tampered[offset] ^= 1
            path = Path(directory) / f"{name}.ota"
            path.write_bytes(tampered)
            if verify(path) == 0:
                raise SystemExit(f"[TEST] FAIL: tampered {name} was accepted")
            print(f"[TEST] PASS: tampered {name} rejected")


if __name__ == "__main__":
    main()
