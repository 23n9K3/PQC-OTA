#!/usr/bin/env python3
"""Send encrypted/signed firmware.ota to the Bootloader over classic CAN."""

from __future__ import annotations

import argparse
import logging
import math
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

from can_protocol import (
    OTA_CAN_REQUEST_ID, OTA_CAN_STATUS_ID, build_request, parse_status,
    split_stream,
)
from ota_format import OTA_CMD_ACK, OTA_CMD_DATA, OTA_CMD_END, OTA_CMD_ERROR, OTA_CMD_START, parse_ota


class _SuppressPcanUptimeWarning(logging.Filter):
    """Hide only python-can's harmless optional uptime dependency warning."""

    def filter(self, record: logging.LogRecord) -> bool:
        return "uptime library not available" not in record.getMessage()


logging.getLogger("can.pcan").addFilter(_SuppressPcanUptimeWarning())

try:
    import can
except ImportError as exc:
    raise SystemExit("缺少python-can，请执行：python -m pip install python-can") from exc


# Keep START acknowledgements distinct from DATA sequence 0.  Some CAN
# adapters retain/retry START frames while the target is held in reset.
OTA_CAN_START_SEQUENCE = 0xFFFF
TRACE_EPOCH = time.monotonic()
DEFAULT_PROGRAMMER_PATHS = (
    Path(r"D:\STMicroelectronics\STM32Cube\STM32CubeProgrammer\bin\STM32_Programmer_CLI.exe"),
    Path(r"C:\Program Files\STMicroelectronics\STM32Cube\STM32CubeProgrammer\bin\STM32_Programmer_CLI.exe"),
    Path(r"C:\Program Files (x86)\STMicroelectronics\STM32Cube\STM32CubeProgrammer\bin\STM32_Programmer_CLI.exe"),
)

CMD_NAMES = {
    OTA_CMD_START: "START",
    OTA_CMD_DATA: "DATA",
    OTA_CMD_END: "END",
    OTA_CMD_ACK: "ACK",
    OTA_CMD_ERROR: "ERROR",
}

ERROR_DESCRIPTIONS = {
    4: "OTA Header校验失败",
    5: "APP_B Flash擦除失败",
    6: "DATA帧超时、格式、命令或序号错误",
    8: "APP_B Flash写入失败",
    9: "END帧错误",
    10: "解密后SHA-256不匹配",
    11: "Metadata保存失败",
    14: "ML-DSA-65发布者签名验证失败",
    15: "APP_B Manifest写入失败",
    17: "APP_B Secure Boot复验失败",
    18: "AES密钥ID不匹配",
    19: "AES-GCM解密初始化失败",
    20: "AES-GCM认证Tag失败",
}


def command_name(cmd: int) -> str:
    return CMD_NAMES.get(cmd, f"UNKNOWN(0x{cmd:02X})")


def trace_frame(direction: str, arbitration_id: int, cmd: int, seq: int,
                raw: bytes, value: int | None = None) -> None:
    detail = "" if value is None else f" value={value}"
    print(f"[CAN-{direction} +{time.monotonic() - TRACE_EPOCH:8.3f}s] "
          f"id=0x{arbitration_id:03X} "
          f"cmd={command_name(cmd)} seq={seq} dlc={len(raw)} "
          f"data={raw.hex(' ').upper()}{detail}")


def send_request(bus: "can.BusABC", cmd: int, seq: int,
                 payload: bytes = b"", trace: bool = False) -> None:
    raw = build_request(cmd, seq, payload)
    if trace:
        trace_frame("TX", OTA_CAN_REQUEST_ID, cmd, seq, raw)
    bus.send(can.Message(arbitration_id=OTA_CAN_REQUEST_ID,
                         is_extended_id=False,
                         data=raw), timeout=1.0)


def wait_status(bus: "can.BusABC", seq: int, timeout: float,
                trace: bool = False) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        message = bus.recv(timeout=max(0.0, deadline - time.monotonic()))
        if message is None:
            break
        if message.is_extended_id or message.arbitration_id != OTA_CAN_STATUS_ID:
            continue
        raw = bytes(message.data)
        cmd, ack_seq, code = parse_status(raw)
        if trace:
            trace_frame("RX", OTA_CAN_STATUS_ID, cmd, ack_seq, raw, code)
        if ack_seq != (seq & 0xFFFF):
            continue
        if cmd == OTA_CMD_ERROR:
            description = ERROR_DESCRIPTIONS.get(code, "未定义错误")
            raise RuntimeError(
                f"Bootloader CAN ERROR: seq={ack_seq}, code={code} ({description})")
        if cmd != OTA_CMD_ACK:
            raise RuntimeError(f"未知CAN状态命令: 0x{cmd:02X}")
        return code
    raise TimeoutError(f"等待CAN ACK超时，seq={seq & 0xFFFF}")


def wait_for_bootloader(bus: "can.BusABC", total_size: int,
                        start_timeout: float, ack_timeout: float,
                        verbose: bool = False,
                        reset_already_done: bool = False) -> None:
    deadline = time.monotonic() + start_timeout
    attempts = 0
    if reset_already_done:
        print("[CAN] Waiting for Bootloader START ACK after auto-reset")
    else:
        print("[CAN] Waiting for Bootloader; reset the board now")
    while time.monotonic() < deadline:
        attempts += 1
        send_request(bus, OTA_CMD_START, OTA_CAN_START_SEQUENCE,
                     struct.pack("<I", total_size),
                     trace=(verbose or attempts == 1))
        try:
            # Retry quickly enough to hit the Bootloader's one-second entry window.
            wait_status(bus, OTA_CAN_START_SEQUENCE,
                        min(0.2, max(0.05, deadline - time.monotonic())),
                        trace=verbose)
            print(f"[CAN] START acknowledged, total={total_size}, "
                  f"attempts={attempts}")
            return
        except TimeoutError:
            if attempts % 5 == 0:
                elapsed = start_timeout - max(0.0, deadline - time.monotonic())
                action = "checking auto-reset/CAN link" if reset_already_done else "press RESET now"
                print(f"[CAN] Still waiting for status_id=0x{OTA_CAN_STATUS_ID:03X}: "
                      f"attempts={attempts}, elapsed={elapsed:.1f}s; "
                      f"{action}")
            continue
    raise RuntimeError(
        f"Bootloader CAN START超时：已发送{attempts}次id=0x{OTA_CAN_REQUEST_ID:03X} "
        f"START，但未收到id=0x{OTA_CAN_STATUS_ID:03X} ACK。"
        "请使用--auto-reset，或在Waiting提示出现后立即按RESET")


def find_programmer_cli(explicit_path: str | None) -> Path:
    if explicit_path:
        path = Path(explicit_path)
        if path.is_file():
            return path
        raise FileNotFoundError(f"STM32_Programmer_CLI不存在: {path}")

    from_path = shutil.which("STM32_Programmer_CLI.exe")
    if from_path:
        return Path(from_path)
    for path in DEFAULT_PROGRAMMER_PATHS:
        if path.is_file():
            return path
    raise FileNotFoundError(
        "未找到STM32_Programmer_CLI.exe；请安装STM32CubeProgrammer或使用"
        "--programmer-cli指定路径")


def reset_board_with_stlink(explicit_path: str | None) -> None:
    cli = find_programmer_cli(explicit_path)
    print(f"[CAN] Auto-reset: use {cli}")
    result = subprocess.run(
        [str(cli), "-c", "port=SWD", "mode=UR", "-rst"],
        text=True, capture_output=True, timeout=15, check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"ST-LINK自动复位失败(code={result.returncode}): {detail}")
    print("[CAN] Auto-reset: MCU reset OK; Bootloader entry window is open")


def print_ota_summary(path: Path, ota: bytes, header, frame_count: int) -> None:
    publisher = header.publisher_id.rstrip(b"\0").decode("ascii", errors="replace")
    header_size = len(ota) - header.signature_size - header.payload_size
    print(f"[CAN] OTA file={path.resolve()}")
    print(f"[CAN] Wire request_id=0x{OTA_CAN_REQUEST_ID:03X} "
          f"status_id=0x{OTA_CAN_STATUS_ID:03X} classic_CAN_payload=4")
    print(f"[CAN] Layout: header={header_size} signature={header.signature_size} "
          f"ciphertext={header.payload_size} total={len(ota)}")
    print(f"[CAN] Firmware: version={header.firmware_version} "
          f"plaintext_size={header.firmware_size} DATA_frames={frame_count}")
    print(f"[SEC] publisher={publisher} key_id={header.key_id.hex()}")
    print(f"[SEC] firmware_sha256={header.firmware_hash.hex()}")
    print(f"[AES-GCM] key_id={header.encryption_key_id.hex()} "
          f"nonce={header.nonce.hex()} tag={header.authentication_tag.hex()}")


def should_trace_data(seq: int, frame_count: int,
                      trace_every: int, verbose: bool) -> bool:
    return (verbose or seq < 4 or seq + 1 == frame_count or
            (trace_every > 0 and seq % trace_every == 0))


def main() -> None:
    parser = argparse.ArgumentParser(description="通过经典CAN发送STM32加密签名OTA")
    parser.add_argument("--file", required=True, help="firmware.ota")
    parser.add_argument("--interface", default="pcan",
                        help="python-can接口，例如pcan/slcan/vector/socketcan")
    parser.add_argument("--channel", default="PCAN_USBBUS1",
                        help="适配器通道，例如PCAN_USBBUS1、COM5、can0")
    parser.add_argument("--bitrate", type=int, default=500000)
    parser.add_argument("--start-timeout", type=float, default=15.0)
    parser.add_argument("--ack-timeout", type=float, default=60.0,
                        help="ACK超时，默认60秒以覆盖ML-DSA验签和Flash擦除")
    parser.add_argument("--trace-every", type=int, default=128,
                        help="每N个DATA帧输出一次原始CAN数据，0表示只输出首尾帧")
    parser.add_argument("--verbose", action="store_true",
                        help="输出每个CAN TX/RX帧（日志量较大）")
    parser.add_argument("--auto-reset", action="store_true",
                        help="PCAN打开后通过ST-LINK自动复位MCU")
    parser.add_argument("--programmer-cli",
                        help="STM32_Programmer_CLI.exe路径，通常无需指定")
    args = parser.parse_args()

    if args.trace_every < 0:
        parser.error("--trace-every不能小于0")

    ota_path = Path(args.file)
    ota = ota_path.read_bytes()
    header, _, _, _ = parse_ota(ota)
    frame_count = math.ceil(len(ota) / 4)
    header_size = len(ota) - header.signature_size - header.payload_size
    signature_end = header_size + header.signature_size
    print_ota_summary(ota_path, ota, header, frame_count)
    print(f"[CAN] Adapter: interface={args.interface} channel={args.channel} "
          f"bitrate={args.bitrate}")
    filters = [{"can_id": OTA_CAN_STATUS_ID, "can_mask": 0x7FF,
                "extended": False}]

    with can.Bus(interface=args.interface, channel=args.channel,
                 bitrate=args.bitrate, can_filters=filters,
                 receive_own_messages=False) as bus:
        started_at = time.monotonic()
        if args.auto_reset:
            reset_board_with_stlink(args.programmer_cli)
        wait_for_bootloader(bus, len(ota), args.start_timeout,
                            args.ack_timeout, args.verbose, args.auto_reset)
        print(f"[CAN] Transfer phase 1/3: Header bytes [0, {header_size})")
        seq = 0
        sent = 0
        transfer_phase = 1
        next_progress = 10
        for chunk in split_stream(ota):
            trace = should_trace_data(seq, frame_count,
                                      args.trace_every, args.verbose)
            send_request(bus, OTA_CMD_DATA, seq, chunk, trace=trace)
            acknowledged = wait_status(bus, seq, args.ack_timeout, trace=trace)
            sent += len(chunk)
            if acknowledged != sent:
                raise RuntimeError(f"Bootloader接收长度不一致：PC={sent}, MCU={acknowledged}")
            if transfer_phase == 1 and sent >= header_size:
                transfer_phase = 2
                print(f"[CAN] Transfer phase 2/3: ML-DSA signature bytes "
                      f"[{header_size}, {signature_end})")
            if transfer_phase == 2 and sent >= signature_end:
                transfer_phase = 3
                print(f"[CAN] Transfer phase 3/3: AES-GCM ciphertext bytes "
                      f"[{signature_end}, {len(ota)})")
            seq = (seq + 1) & 0xFFFF
            percent = sent * 100 // len(ota)
            if percent >= next_progress or sent == len(ota):
                print(f"[CAN] Progress: {sent}/{len(ota)} bytes "
                      f"({percent}%), last_ack={acknowledged}, frames={seq}")
                while next_progress <= percent:
                    next_progress += 10

        print("[CAN] Finalize: send END; Bootloader checks AES-GCM, SHA-256, "
              "Secure Boot Manifest and Metadata")
        send_request(bus, OTA_CMD_END, seq, trace=True)
        wait_status(bus, seq, max(args.ack_timeout, 60.0), trace=True)
        elapsed = time.monotonic() - started_at
        print("[CAN] Finalize: final ACK received")
        print(f"[CAN] OTA SUCCESS, firmware version={header.firmware_version}, "
              f"elapsed={elapsed:.2f}s")
        print("[CAN] Board is rebooting to APP_B; use UART only to view debug logs")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[CAN][STOP] Cancelled by user")
        raise SystemExit(130)
    except Exception as exc:
        # Print to stdout so Windows PowerShell + Tee-Object records a clean,
        # readable diagnostic instead of wrapping stderr as NativeCommandError.
        print(f"[CAN][FATAL] {type(exc).__name__}: {exc}")
        raise SystemExit(1)
