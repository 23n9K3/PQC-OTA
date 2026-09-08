#!/usr/bin/env python3
"""Host regression tests for persistent APP Secure Boot Manifests."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from ota_format import APP_MANIFEST_SIGNATURE_OFFSET


SCRIPT_DIR = Path(__file__).resolve().parent


def verify(manifest: Path, app: Path) -> int:
    return subprocess.run(
        [sys.executable, str(SCRIPT_DIR / "verify_manifest.py"),
         "--manifest", str(manifest), "--app", str(app)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode


def main() -> None:
    pairs = [
        (SCRIPT_DIR / "app_a_manifest.bin", SCRIPT_DIR / "app_a.bin"),
        (SCRIPT_DIR / "app_b_manifest.bin", SCRIPT_DIR / "app_b.bin"),
    ]
    for manifest, app in pairs:
        if verify(manifest, app) != 0:
            raise SystemExit(f"[SECURE-BOOT TEST] FAIL: valid {app.name} rejected")
        print(f"[SECURE-BOOT TEST] PASS: valid {app.name} accepted")

    with tempfile.TemporaryDirectory(prefix="upqc_secure_boot_") as directory:
        temp = Path(directory)
        manifest, app = pairs[1]

        modified_app = bytearray(app.read_bytes())
        modified_app[-1] ^= 1
        modified_app_path = temp / "tampered_app_b.bin"
        modified_app_path.write_bytes(modified_app)
        if verify(manifest, modified_app_path) == 0:
            raise SystemExit("[SECURE-BOOT TEST] FAIL: tampered APP accepted")
        print("[SECURE-BOOT TEST] PASS: tampered APP rejected")

        modified_manifest = bytearray(manifest.read_bytes())
        modified_manifest[APP_MANIFEST_SIGNATURE_OFFSET] ^= 1
        modified_manifest_path = temp / "tampered_manifest.bin"
        modified_manifest_path.write_bytes(modified_manifest)
        if verify(modified_manifest_path, app) == 0:
            raise SystemExit("[SECURE-BOOT TEST] FAIL: tampered Manifest accepted")
        print("[SECURE-BOOT TEST] PASS: tampered Manifest rejected")

        if verify(pairs[0][0], pairs[1][1]) == 0:
            raise SystemExit("[SECURE-BOOT TEST] FAIL: wrong slot image accepted")
        print("[SECURE-BOOT TEST] PASS: mismatched image/Manifest rejected")


if __name__ == "__main__":
    main()
