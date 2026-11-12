"""Firmware analysis tests, using a generated fixture binary."""

import hashlib
import struct

import pytest

from boardaudit.analysis import (
    analyze_firmware,
    entropy,
    extract_strings,
    parse_esp_partitions,
    sha256_hex,
)


def make_fixture(tmp_path, secret=b"AKIAIOSFODNN7EXAMPLE"):
    data = bytearray(b"\x00" * 0x9000)
    data[0:5] = b"HELLO"
    # Printable strings after the header.
    payload = b"boardaudit test firmware\x00version 1.2.3\x00" + secret + b"\x00"
    data[0x100:0x100 + len(payload)] = payload
    # ESP partition table at 0x8000: one app entry.
    entry = bytearray(32)
    entry[0:2] = b"\xaa\x50"
    entry[2] = 0  # type app
    entry[3] = 0  # subtype factory
    struct.pack_into("<I", entry, 4, 0x10000)
    struct.pack_into("<I", entry, 8, 0x100000)
    entry[12:28] = b"factory\x00" + b"\x00" * 8
    data[0x8000:0x8000 + 32] = entry
    path = tmp_path / "firmware.bin"
    path.write_bytes(bytes(data))
    return path, bytes(data)


def test_extract_strings():
    assert "xxhello" in extract_strings(b"xxhello\x00world\x00")
    assert "world" in extract_strings(b"xxhello\x00world\x00")
    assert extract_strings(b"\x00\x01\x02") == []


def test_sha256_and_entropy():
    data = b"abc"
    assert sha256_hex(data) == hashlib.sha256(data).hexdigest()
    assert entropy(b"") == 0.0
    assert 0.0 < entropy(b"abcdefgh") <= 8.0


def test_parse_esp_partitions(tmp_path):
    path, _ = make_fixture(tmp_path)
    data = path.read_bytes()
    parts = parse_esp_partitions(data)
    assert len(parts) == 1
    assert parts[0]["name"] == "factory"
    assert parts[0]["offset"] == 0x10000
    assert parts[0]["size"] == 0x100000


def test_parse_no_partition_table():
    assert parse_esp_partitions(b"\x00" * 0x9000) == []


def test_analyze_firmware_redacts_secret(tmp_path):
    path, data = make_fixture(tmp_path)
    report = analyze_firmware(path)
    assert report["sha256"] == hashlib.sha256(data).hexdigest()
    assert report["size_bytes"] == len(data)
    assert report["partitions"][0]["name"] == "factory"
    assert report["score"] >= 40
    assert report["risk_level"] in ("low", "medium", "high", "critical")
    assert b"AKIAIOSFODNN7EXAMPLE".decode() not in str(report)
    assert report["findings"]
    assert report["findings"][0]["preview"].startswith("AKIA")


def test_analyze_missing_file():
    with pytest.raises(FileNotFoundError):
        analyze_firmware("/nonexistent/firmware.bin")
