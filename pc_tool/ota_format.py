#!/usr/bin/env python3
"""Encrypted and signed OTA v3 format shared by all PC tools.

firmware.ota = 148-byte header + 3309-byte ML-DSA-65 signature
               + AES-256-GCM ciphertext

The GCM AAD is the complete header with authentication_tag and header_crc32
zeroed. The final header (including nonce/tag) is signed with ML-DSA-65.
"""

from __future__ import annotations

import binascii
import hashlib
import struct
from dataclasses import dataclass, replace

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OTA_FILE_MAGIC = 0x31544F55
OTA_HEADER_VERSION = 3
OTA_HEADER_FORMAT = "<IIIII32sI16s16sIII16s12s16sI"
OTA_HEADER_SIZE = struct.calcsize(OTA_HEADER_FORMAT)
OTA_PUBLISHER_ID_SIZE = 16
OTA_KEY_ID_SIZE = 16
OTA_ENCRYPTION_KEY_ID_SIZE = 16
OTA_GCM_NONCE_SIZE = 12
OTA_GCM_TAG_SIZE = 16
OTA_AES_256_KEY_SIZE = 32
OTA_SIGNATURE_ALGORITHM_ML_DSA_65 = 1
OTA_ENCRYPTION_ALGORITHM_AES_256_GCM = 1
ML_DSA_65_PUBLIC_KEY_SIZE = 1952
ML_DSA_65_SECRET_KEY_SIZE = 4032
ML_DSA_65_SIGNATURE_SIZE = 3309
APP_MANIFEST_PAGE_SIZE = 4096
APP_MANIFEST_SIGNATURE_OFFSET = 152
OTA_FRAME_SOF = 0xA5
OTA_CMD_START = 0x01
OTA_CMD_DATA = 0x02
OTA_CMD_END = 0x03
OTA_CMD_ACK = 0x79
OTA_CMD_ERROR = 0x1F
OTA_PACKET_MAX = 512


@dataclass
class OtaHeader:
    magic: int
    header_version: int
    firmware_version: int
    firmware_size: int
    payload_size: int
    firmware_hash: bytes
    flags: int
    publisher_id: bytes
    key_id: bytes
    signature_algorithm: int
    signature_size: int
    encryption_algorithm: int
    encryption_key_id: bytes
    nonce: bytes
    authentication_tag: bytes
    header_crc32: int = 0


def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def encode_identity(value: str, size: int, field_name: str) -> bytes:
    encoded = value.encode("ascii")
    if not encoded or len(encoded) > size:
        raise ValueError(f"{field_name}必须是1到{size}字节ASCII")
    return encoded.ljust(size, b"\0")


def key_id_from_public_key(public_key: bytes) -> bytes:
    if len(public_key) != ML_DSA_65_PUBLIC_KEY_SIZE:
        raise ValueError("ML-DSA-65公钥长度错误")
    return hashlib.sha256(public_key).digest()[:OTA_KEY_ID_SIZE]


def encryption_key_id_from_key(key: bytes) -> bytes:
    if len(key) != OTA_AES_256_KEY_SIZE:
        raise ValueError("AES-256密钥必须是32字节")
    return hashlib.sha256(key).digest()[:OTA_ENCRYPTION_KEY_ID_SIZE]


def build_header(payload: bytes, version: int, publisher_id: bytes,
                 key_id: bytes, encryption_key_id: bytes, nonce: bytes,
                 flags: int = 0) -> OtaHeader:
    if len(publisher_id) != OTA_PUBLISHER_ID_SIZE:
        raise ValueError("publisher_id长度错误")
    if len(key_id) != OTA_KEY_ID_SIZE:
        raise ValueError("key_id长度错误")
    if len(encryption_key_id) != OTA_ENCRYPTION_KEY_ID_SIZE:
        raise ValueError("encryption_key_id长度错误")
    if len(nonce) != OTA_GCM_NONCE_SIZE:
        raise ValueError("AES-GCM nonce必须是12字节")
    return OtaHeader(
        magic=OTA_FILE_MAGIC, header_version=OTA_HEADER_VERSION,
        firmware_version=version, firmware_size=len(payload),
        payload_size=len(payload), firmware_hash=hashlib.sha256(payload).digest(),
        flags=flags, publisher_id=publisher_id, key_id=key_id,
        signature_algorithm=OTA_SIGNATURE_ALGORITHM_ML_DSA_65,
        signature_size=ML_DSA_65_SIGNATURE_SIZE,
        encryption_algorithm=OTA_ENCRYPTION_ALGORITHM_AES_256_GCM,
        encryption_key_id=encryption_key_id, nonce=nonce,
        authentication_tag=b"\0" * OTA_GCM_TAG_SIZE,
    )


def _pack_header_fields(header: OtaHeader, crc_value: int) -> bytes:
    return struct.pack(
        OTA_HEADER_FORMAT, header.magic, header.header_version,
        header.firmware_version, header.firmware_size, header.payload_size,
        header.firmware_hash, header.flags, header.publisher_id, header.key_id,
        header.signature_algorithm, header.signature_size,
        header.encryption_algorithm, header.encryption_key_id, header.nonce,
        header.authentication_tag, crc_value,
    )


def gcm_aad(header: OtaHeader) -> bytes:
    """Canonical AAD: header with tag and CRC zeroed."""
    aad_header = replace(header, authentication_tag=b"\0" * OTA_GCM_TAG_SIZE,
                         header_crc32=0)
    return _pack_header_fields(aad_header, 0)


def pack_header(header: OtaHeader) -> bytes:
    header.header_crc32 = crc32(_pack_header_fields(header, 0))
    return _pack_header_fields(header, header.header_crc32)


def parse_header(raw: bytes) -> OtaHeader:
    if len(raw) != OTA_HEADER_SIZE:
        raise ValueError(f"OTA Header长度错误，需要{OTA_HEADER_SIZE}字节")
    return OtaHeader(*struct.unpack(OTA_HEADER_FORMAT, raw))


def validate_header(raw: bytes) -> OtaHeader:
    header = parse_header(raw)
    if header.magic != OTA_FILE_MAGIC:
        raise ValueError("OTA magic错误")
    if header.header_version != OTA_HEADER_VERSION:
        raise ValueError("OTA header_version错误")
    if header.firmware_size == 0 or header.payload_size != header.firmware_size:
        raise ValueError("固件长度字段错误")
    if header.signature_algorithm != OTA_SIGNATURE_ALGORITHM_ML_DSA_65:
        raise ValueError("签名算法不是ML-DSA-65")
    if header.signature_size != ML_DSA_65_SIGNATURE_SIZE:
        raise ValueError("ML-DSA-65签名长度错误")
    if header.encryption_algorithm != OTA_ENCRYPTION_ALGORITHM_AES_256_GCM:
        raise ValueError("加密算法不是AES-256-GCM")
    if crc32(_pack_header_fields(header, 0)) != header.header_crc32:
        raise ValueError("OTA Header CRC32错误")
    return header


def decrypt_payload(header: OtaHeader, ciphertext: bytes, aes_key: bytes) -> bytes:
    if encryption_key_id_from_key(aes_key) != header.encryption_key_id:
        raise ValueError("OTA encryption_key_id与AES密钥不匹配")
    if len(ciphertext) != header.payload_size:
        raise ValueError("密文长度和Header不一致")
    plaintext = AESGCM(aes_key).decrypt(
        header.nonce, ciphertext + header.authentication_tag, gcm_aad(header))
    if len(plaintext) != header.firmware_size:
        raise ValueError("解密后固件长度错误")
    if hashlib.sha256(plaintext).digest() != header.firmware_hash:
        raise ValueError("解密后固件SHA-256和Header不一致")
    return plaintext


def parse_ota(ota: bytes) -> tuple[OtaHeader, bytes, bytes, bytes]:
    if len(ota) < OTA_HEADER_SIZE:
        raise ValueError("firmware.ota太小")
    header_raw = ota[:OTA_HEADER_SIZE]
    header = validate_header(header_raw)
    signature_end = OTA_HEADER_SIZE + header.signature_size
    if len(ota) != signature_end + header.payload_size:
        raise ValueError("firmware.ota总长度与Header不一致")
    return header, header_raw, ota[OTA_HEADER_SIZE:signature_end], ota[signature_end:]


def build_app_manifest(header_raw: bytes, signature: bytes) -> bytes:
    if len(header_raw) != OTA_HEADER_SIZE:
        raise ValueError("Manifest Header长度错误")
    if len(signature) != ML_DSA_65_SIGNATURE_SIZE:
        raise ValueError("Manifest ML-DSA-65签名长度错误")
    prefix = header_raw.ljust(APP_MANIFEST_SIGNATURE_OFFSET, b"\xFF") + signature
    if len(prefix) > APP_MANIFEST_PAGE_SIZE:
        raise ValueError("Manifest超过4 KB")
    return prefix.ljust(APP_MANIFEST_PAGE_SIZE, b"\xFF")


def parse_app_manifest(manifest: bytes) -> tuple[OtaHeader, bytes, bytes]:
    if len(manifest) != APP_MANIFEST_PAGE_SIZE:
        raise ValueError("App Manifest必须是4096字节")
    header_raw = manifest[:OTA_HEADER_SIZE]
    header = validate_header(header_raw)
    signature = manifest[APP_MANIFEST_SIGNATURE_OFFSET:
                         APP_MANIFEST_SIGNATURE_OFFSET + header.signature_size]
    if len(signature) != ML_DSA_65_SIGNATURE_SIZE:
        raise ValueError("App Manifest签名不完整")
    return header, header_raw, signature


def build_frame(cmd: int, seq: int, payload: bytes = b"") -> bytes:
    if len(payload) > OTA_PACKET_MAX:
        raise ValueError("单包payload超过OTA_PACKET_MAX")
    body = struct.pack("<BHH", cmd, seq & 0xFFFF, len(payload)) + payload
    return bytes([OTA_FRAME_SOF]) + body + struct.pack("<I", crc32(body))


def parse_status_frame(frame: bytes) -> tuple[int, int, int]:
    if len(frame) != 14 or frame[0] != OTA_FRAME_SOF:
        raise ValueError("ACK/ERROR帧错误")
    cmd, seq, length = struct.unpack("<BHH", frame[1:6])
    if length != 4:
        raise ValueError("ACK/ERROR payload长度错误")
    recv_crc = struct.unpack("<I", frame[10:14])[0]
    if crc32(frame[1:10]) != recv_crc:
        raise ValueError("ACK/ERROR CRC错误")
    return cmd, seq, struct.unpack("<I", frame[6:10])[0]
