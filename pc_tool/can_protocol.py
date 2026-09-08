#!/usr/bin/env python3
"""Classic CAN wire format used by the Bootloader OTA transport."""

from __future__ import annotations

import struct

OTA_CAN_REQUEST_ID = 0x600
OTA_CAN_STATUS_ID = 0x601
OTA_CAN_DATA_BYTES = 4


def build_request(cmd: int, seq: int, payload: bytes = b"") -> bytes:
    if len(payload) > OTA_CAN_DATA_BYTES:
        raise ValueError("CAN OTA payload最多4字节")
    return bytes((cmd & 0xFF, seq & 0xFF, (seq >> 8) & 0xFF, len(payload))) + payload


def parse_request(data: bytes) -> tuple[int, int, bytes]:
    if len(data) < 4:
        raise ValueError("CAN OTA请求帧太短")
    cmd, seq_low, seq_high, length = data[:4]
    if length > OTA_CAN_DATA_BYTES or len(data) != 4 + length:
        raise ValueError("CAN OTA请求帧长度错误")
    return cmd, seq_low | (seq_high << 8), data[4:]


def build_status(cmd: int, seq: int, code: int) -> bytes:
    return bytes((cmd & 0xFF, seq & 0xFF, (seq >> 8) & 0xFF)) + struct.pack("<I", code)


def parse_status(data: bytes) -> tuple[int, int, int]:
    if len(data) != 7:
        raise ValueError("CAN OTA状态帧必须是7字节")
    return data[0], data[1] | (data[2] << 8), struct.unpack("<I", data[3:7])[0]


def split_stream(data: bytes):
    for offset in range(0, len(data), OTA_CAN_DATA_BYTES):
        yield data[offset:offset + OTA_CAN_DATA_BYTES]
