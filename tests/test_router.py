"""Router firmware analysis and gateway validation tests."""

import struct

import pytest

from boardaudit.router import (
    ROUTER_PROFILES,
    analyze_router_firmware,
    detect_router_formats,
    get_router_profile,
    list_router_profiles,
    parse_trx_header,
    parse_uimage_header,
    validate_gateway,
)

# AWS documentation example key, built from parts so the literal
# value is only assembled at runtime. It is not a real credential.
EXAMPLE_KEY = b"AKIA" + b"IOSFODNN7EXAMPLE"


def make_uimage(tmp_path, name=b"test-router"):
    """Build a small router firmware file with a uImage header."""
    data = bytearray(b"\x00" * 0x2000)
    header = struct.pack(
        ">7I4B32s",
        0x27051956,  # magic
        0,  # header crc
        1700000000,  # timestamp
        0x1000,  # size
        0x80000000,  # load address
        0x80000000,  # entry point
        0,  # data crc
        5,  # os (linux)
        2,  # arch (mips)
        2,  # type (kernel)
        1,  # compression (gzip)
        name + b"\x00" * (32 - len(name)),
    )
    data[0:64] = header
    # SquashFS magic at 0x1000, plus strings with findings.
    data[0x1000:0x1004] = b"hsqs"
    payload = (
        b"telnet enabled\x00admin=admin\x00"
        + EXAMPLE_KEY
        + b"\x00http://192.168.1.1/admin\x00"
    )
    data[0x1100 : 0x1100 + len(payload)] = payload
    path = tmp_path / "router.bin"
    path.write_bytes(bytes(data))
    return path


def make_trx(tmp_path):
    data = bytearray(b"\x00" * 0x2000)
    header = b"HDR0" + struct.pack("<6I", 0x1000, 0, 0, 0x1C, 0x1000, 0x2000)
    data[0 : len(header)] = header
    path = tmp_path / "router.trx"
    path.write_bytes(bytes(data))
    return path


def test_router_profiles_present():
    expected = {
        "mediatek-mt7620",
        "mediatek-mt7621",
        "mediatek-mt7981",
        "mediatek-mt7986",
        "qca9531",
        "qca9563",
        "qca-ipq4019",
        "qca-ipq8074",
        "bcm63xx",
        "bcm47xx",
        "rtl8197",
        "rtl8676",
        "generic-openwrt",
    }
    assert set(ROUTER_PROFILES) == expected
    for profile in list_router_profiles():
        assert profile.flash_size > 0
        assert profile.filesystem
        assert profile.acquisition_notes


def test_unknown_router_profile():
    with pytest.raises(ValueError):
        get_router_profile("not-a-soc")


def test_detect_router_formats(tmp_path):
    path = make_uimage(tmp_path)
    formats = detect_router_formats(path.read_bytes())
    names = {entry["format"] for entry in formats}
    assert "uimage" in names
    assert "squashfs" in names


def test_parse_uimage_header(tmp_path):
    path = make_uimage(tmp_path)
    header = parse_uimage_header(path.read_bytes(), 0)
    assert header is not None
    assert header["name"] == "test-router"
    assert header["size"] == 0x1000
    assert header["load_address"] == 0x80000000


def test_parse_uimage_header_missing():
    assert parse_uimage_header(b"\x00" * 128, 0) is None


def test_parse_trx_header(tmp_path):
    path = make_trx(tmp_path)
    header = parse_trx_header(path.read_bytes(), 0)
    assert header is not None
    assert header["length"] == 0x1000
    assert header["partition_offsets"] == [0x1C, 0x1000, 0x2000]


def test_parse_trx_header_missing():
    assert parse_trx_header(b"\x00" * 128, 0) is None


def test_analyze_router_firmware(tmp_path):
    path = make_uimage(tmp_path)
    report = analyze_router_firmware(path)
    assert report["kind"] == "router"
    assert report["uimage_header"] is not None
    assert report["uimage_header"]["name"] == "test-router"
    assert {"filesystem": "squashfs", "offset": 0x1000} in report["filesystems"]
    assert report["score"] >= 40
    assert report["risk_level"] in ("low", "medium", "high", "critical")
    # The full example key must never appear in the report.
    assert EXAMPLE_KEY.decode() not in str(report)
    rules = {f["rule"] for f in report["findings"]}
    assert "aws_access_key" in rules
    assert "router_default_credential" in rules
    assert "router_telnet_service" in rules
    for finding in report["findings"]:
        assert finding["severity"] in ("low", "medium", "high", "critical")
        assert finding["remediation"]


def test_analyze_router_missing_file():
    with pytest.raises(FileNotFoundError):
        analyze_router_firmware("/nonexistent/router.bin")


def test_validate_gateway_private_ok():
    assert validate_gateway("192.168.1.1") == "192.168.1.1"
    assert validate_gateway("10.0.0.1") == "10.0.0.1"
    assert validate_gateway("172.16.0.254") == "172.16.0.254"


def test_validate_gateway_rejects_public():
    with pytest.raises(ValueError):
        validate_gateway("8.8.8.8")
    with pytest.raises(ValueError):
        validate_gateway("1.1.1.1")


def test_validate_gateway_rejects_localhost():
    with pytest.raises(ValueError):
        validate_gateway("127.0.0.1")
    with pytest.raises(ValueError):
        validate_gateway("localhost")
    with pytest.raises(ValueError):
        validate_gateway("256.1.1.1")
    with pytest.raises(ValueError):
        validate_gateway("0.0.0.0")
    with pytest.raises(ValueError):
        validate_gateway("")
