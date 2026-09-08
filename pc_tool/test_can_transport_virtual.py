#!/usr/bin/env python3
"""End-to-end python-can virtual-bus test of request/ACK sequencing."""

from __future__ import annotations

import struct
import threading
from pathlib import Path

import can

from can_protocol import (
    OTA_CAN_REQUEST_ID, OTA_CAN_STATUS_ID, build_status, parse_request,
    split_stream,
)
from ota_format import (
    OTA_CMD_ACK, OTA_CMD_DATA, OTA_CMD_END, OTA_CMD_ERROR, OTA_CMD_START,
    decrypt_payload, parse_ota,
)
from send_can import send_request, wait_for_bootloader, wait_status


def device_simulator(bus: "can.BusABC", expected: bytes, result: list[str]) -> None:
    stream = bytearray()
    expected_seq = 0
    try:
        while True:
            message = bus.recv(timeout=2.0)
            if message is None or message.arbitration_id != OTA_CAN_REQUEST_ID:
                raise RuntimeError("device receive timeout")
            cmd, seq, payload = parse_request(bytes(message.data))
            if cmd == OTA_CMD_START:
                if struct.unpack("<I", payload)[0] != len(expected):
                    raise RuntimeError("START size mismatch")
                status = build_status(OTA_CMD_ACK, seq, 0)
            elif cmd == OTA_CMD_DATA:
                if seq != expected_seq:
                    status = build_status(OTA_CMD_ERROR, seq, 6)
                else:
                    stream.extend(payload)
                    expected_seq = (expected_seq + 1) & 0xFFFF
                    status = build_status(OTA_CMD_ACK, seq, len(stream))
            elif cmd == OTA_CMD_END:
                if seq != expected_seq or bytes(stream) != expected:
                    status = build_status(OTA_CMD_ERROR, seq, 9)
                else:
                    status = build_status(OTA_CMD_ACK, seq, 0)
                    result.append("ok")
            else:
                status = build_status(OTA_CMD_ERROR, seq, 1)
            bus.send(can.Message(arbitration_id=OTA_CAN_STATUS_ID,
                                 is_extended_id=False, data=status))
            if cmd == OTA_CMD_END:
                return
    except Exception as exc:
        result.append(str(exc))


def main() -> None:
    root = Path(__file__).resolve().parent
    ota = (root / "firmware.ota").read_bytes()
    result: list[str] = []
    channel = "upqc-ota-can-test"
    host = can.Bus(interface="virtual", channel=channel,
                   receive_own_messages=False)
    device = can.Bus(interface="virtual", channel=channel,
                     receive_own_messages=False)
    thread = threading.Thread(target=device_simulator,
                              args=(device, ota, result), daemon=True)
    thread.start()
    try:
        wait_for_bootloader(host, len(ota), 1.0, 0.2)
        seq = 0
        sent = 0
        for chunk in split_stream(ota):
            send_request(host, OTA_CMD_DATA, seq, chunk)
            sent += len(chunk)
            assert wait_status(host, seq, 1.0) == sent
            seq = (seq + 1) & 0xFFFF
        send_request(host, OTA_CMD_END, seq)
        assert wait_status(host, seq, 1.0) == 0
        thread.join(timeout=2.0)
        assert result == ["ok"], result

        header, _, _, ciphertext = parse_ota(ota)
        key = (root / "keys" / "dev_firmware_aes256_key.bin").read_bytes()
        assert decrypt_payload(header, ciphertext, key) == (root / "app_b.bin").read_bytes()
        print(f"[CAN VIRTUAL] PASS: START + {seq} DATA + END frames with ACK")
        print("[CAN VIRTUAL] PASS: payload authentication/decryption preserved")
    finally:
        host.shutdown()
        device.shutdown()


if __name__ == "__main__":
    main()
