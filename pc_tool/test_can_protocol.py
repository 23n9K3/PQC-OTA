#!/usr/bin/env python3
"""Host-only regression tests for the classic CAN OTA framing."""

from pathlib import Path

from can_protocol import build_request, build_status, parse_request, parse_status, split_stream
from ota_format import OTA_CMD_ACK, OTA_CMD_DATA, decrypt_payload, parse_ota


def main() -> None:
    ota = Path(__file__).with_name("firmware.ota").read_bytes()
    rebuilt = bytearray()
    expected_seq = 0
    for chunk in split_stream(ota):
        wire = build_request(OTA_CMD_DATA, expected_seq, chunk)
        cmd, seq, payload = parse_request(wire)
        assert cmd == OTA_CMD_DATA and seq == expected_seq
        rebuilt.extend(payload)
        status = build_status(OTA_CMD_ACK, seq, len(rebuilt))
        assert parse_status(status) == (OTA_CMD_ACK, seq, len(rebuilt))
        expected_seq = (expected_seq + 1) & 0xFFFF
    assert bytes(rebuilt) == ota
    assert len(list(split_stream(ota))) == (len(ota) + 3) // 4
    header, _, _, ciphertext = parse_ota(bytes(rebuilt))
    key = Path(__file__).with_name("keys").joinpath("dev_firmware_aes256_key.bin").read_bytes()
    plaintext = decrypt_payload(header, ciphertext, key)
    assert plaintext == Path(__file__).with_name("app_b.bin").read_bytes()
    print(f"[CAN TEST] PASS: {len(ota)} bytes, {expected_seq} DATA frames, byte-identical")
    print("[CAN TEST] PASS: reassembled ciphertext authenticated and decrypted")


if __name__ == "__main__":
    main()
