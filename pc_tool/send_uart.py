#!/usr/bin/env python3
"""通过 UART 发送 firmware.ota 到 Bootloader。"""

from __future__ import annotations

import argparse
import struct
import sys
import time
from pathlib import Path

from ota_format import (
    OTA_CMD_ACK,
    OTA_CMD_DATA,
    OTA_CMD_END,
    OTA_CMD_ERROR,
    OTA_CMD_START,
    OTA_PACKET_MAX,
    build_frame,
    parse_ota,
    parse_status_frame,
)

try:
    import serial
except ImportError as exc:
    raise SystemExit("缺少 pyserial，请先执行：pip install pyserial") from exc


def print_boot_log(data: bytearray) -> None:
    if data:
        sys.stdout.write(data.decode("ascii", errors="replace"))
        sys.stdout.flush()
        data.clear()


def read_status(ser: "serial.Serial") -> tuple[int, int, int]:
    deadline = time.monotonic() + ser.timeout
    boot_log = bytearray()

    # Bootloader logs and binary OTA replies share USART3. Display text bytes
    # received before the binary ACK/ERROR SOF instead of silently discarding them.
    while time.monotonic() < deadline:
        byte = ser.read(1)
        if byte != bytes([0xA5]):
            if byte:
                boot_log.extend(byte)
                if byte in (b"\n", b"\r") or len(boot_log) >= 512:
                    print_boot_log(boot_log)
            continue

        print_boot_log(boot_log)
        remaining = 13
        tail = bytearray()
        while remaining > 0 and time.monotonic() < deadline:
            chunk = ser.read(remaining)
            tail.extend(chunk)
            remaining -= len(chunk)

        if remaining == 0:
            return parse_status_frame(bytes([0xA5]) + bytes(tail))

    print_boot_log(boot_log)
    raise RuntimeError("等待 ACK 超时")


def show_post_reboot_log(ser: "serial.Serial", seconds: float) -> None:
    """Keep the port open briefly so reset/Secure Boot/App logs are visible."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        chunk = ser.read(ser.in_waiting or 1)
        if chunk:
            sys.stdout.write(chunk.decode("ascii", errors="replace"))
            sys.stdout.flush()


def wait_for_boot_prompt(ser: "serial.Serial", timeout: float = 10.0) -> None:
    marker = b"Send 'u' within 1 second"
    received = bytearray()
    deadline = time.monotonic() + timeout

    print("[UART] Waiting for Bootloader prompt; reset the board now")
    while time.monotonic() < deadline:
        chunk = ser.read(ser.in_waiting or 1)
        if not chunk:
            continue
        received.extend(chunk)
        sys.stdout.write(chunk.decode("ascii", errors="replace"))
        sys.stdout.flush()
        if marker in received:
            return
        if len(received) > 512:
            del received[:-256]

    raise RuntimeError("Bootloader prompt timeout")


def wait_ack(ser: "serial.Serial", seq: int) -> int:
    cmd, ack_seq, code = read_status(ser)
    if cmd == OTA_CMD_ERROR:
        raise RuntimeError(f"Bootloader 返回 ERROR，seq={ack_seq}, code={code}")
    if cmd != OTA_CMD_ACK:
        raise RuntimeError(f"收到未知回复 cmd=0x{cmd:02X}")
    if ack_seq != (seq & 0xFFFF):
        raise RuntimeError(f"ACK seq 不匹配，期望 {seq & 0xFFFF}，实际 {ack_seq}")
    return code


def print_progress(done: int, total: int) -> None:
    width = 30
    ratio = done / total if total else 1.0
    filled = int(width * ratio)
    bar = "#" * filled + "-" * (width - filled)
    sys.stdout.write(f"\r[UART] [{bar}] {done}/{total} bytes {ratio * 100:5.1f}%")
    sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="通过 UART 发送 STM32 OTA 包")
    parser.add_argument("--port", required=True, help="串口号，例如 COM5")
    parser.add_argument("--baud", type=int, default=115200, help="波特率，默认 115200")
    parser.add_argument("--file", required=True, help="firmware.ota 文件")
    parser.add_argument("--timeout", type=float, default=60.0,
                        help="串口超时秒数，默认60（覆盖ML-DSA验签和Flash擦除）")
    parser.add_argument("--post-wait", type=float, default=3.0,
                        help="成功后继续显示复位/启动日志的秒数，默认3秒")
    args = parser.parse_args()

    ota_path = Path(args.file)
    ota = ota_path.read_bytes()
    header, header_raw, signature, payload = parse_ota(ota)

    print("[UART] 请先复位板子，并在 Bootloader 提示时输入 u 进入 OTA 模式")

    with serial.Serial(args.port, args.baud, timeout=args.timeout, write_timeout=args.timeout) as ser:
        time.sleep(0.2)
        ser.reset_input_buffer()

        wait_for_boot_prompt(ser)

        # 自动发送 u，配合 Bootloader 的 1 秒 OTA 入口窗口。
        ser.write(b"u")
        ser.flush()
        time.sleep(0.05)

        total_size = len(ota)
        print(f"[UART] START total={total_size}")
        ser.write(build_frame(OTA_CMD_START, 0, struct.pack("<I", total_size)))
        wait_ack(ser, 0)

        seq = 0
        print("[UART] Send OTA Header")
        ser.write(build_frame(OTA_CMD_DATA, seq, header_raw))
        wait_ack(ser, seq)
        seq += 1

        print(f"[UART] Send ML-DSA-65 signature ({len(signature)} bytes)")
        signature_sent = 0
        while signature_sent < len(signature):
            chunk = signature[signature_sent : signature_sent + OTA_PACKET_MAX]
            ser.write(build_frame(OTA_CMD_DATA, seq, chunk))
            wait_ack(ser, seq)
            signature_sent += len(chunk)
            print_progress(signature_sent, len(signature))
            seq += 1
        print()
        print(f"[UART] Publisher authenticated, firmware version={header.firmware_version}")

        sent = 0
        while sent < len(payload):
            chunk = payload[sent : sent + OTA_PACKET_MAX]
            ser.write(build_frame(OTA_CMD_DATA, seq, chunk))
            wait_ack(ser, seq)
            sent += len(chunk)
            print_progress(sent, len(payload))
            seq += 1

        print()
        print("[UART] END")
        ser.write(build_frame(OTA_CMD_END, seq, b""))
        wait_ack(ser, seq)
        print("[UART] OTA send done")
        show_post_reboot_log(ser, args.post_wait)


if __name__ == "__main__":
    main()
