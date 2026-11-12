"""Disk image analysis, MBR/GPT parsing, and device-scan safety tests."""

import struct

import pytest

from boardaudit.disk import (
    DiskError,
    analyze_disk_image,
    detect_filesystem,
    disk_device_scan,
    parse_gpt,
    parse_mbr,
    parse_partitions,
    validate_disk_device,
)

# AWS documentation example key, built from parts so the literal
# value is only assembled at runtime. It is not a real credential.
EXAMPLE_KEY = b"AKIA" + b"IOSFODNN7EXAMPLE"


def _gpt_guid_bytes() -> bytes:
    """16-byte GPT type GUID for a Linux filesystem partition."""
    return struct.pack("<IHH", 0x0FC63DAF, 0x8483, 0x4772) + bytes(
        [0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4]
    )


def make_mbr_image(tmp_path):
    """Disk image: MBR with one FAT32 partition, plus a secret string."""
    size = 4 * 1024 * 1024
    data = bytearray(b"\x00" * size)
    data[510:512] = b"\x55\xaa"
    entry = bytearray(16)
    entry[0] = 0x80  # bootable
    entry[4] = 0x0C  # FAT32
    struct.pack_into("<I", entry, 8, 2048)  # start LBA
    struct.pack_into("<I", entry, 12, 4096)  # sectors
    data[446:462] = entry
    part_offset = 2048 * 512
    data[part_offset + 82 : part_offset + 90] = b"FAT32   "
    payload = b"disk test image\x00" + EXAMPLE_KEY + b"\x00"
    data[0x1000 : 0x1000 + len(payload)] = payload
    path = tmp_path / "disk.img"
    path.write_bytes(bytes(data))
    return path


def make_gpt_image(tmp_path):
    """Disk image: GPT header + one Linux filesystem partition entry."""
    size = 4 * 1024 * 1024
    data = bytearray(b"\x00" * size)
    # MBR protective entry so the image also looks like a disk.
    data[510:512] = b"\x55\xaa"
    data[446 + 4] = 0xEE
    struct.pack_into("<I", data, 446 + 8, 1)
    struct.pack_into("<I", data, 446 + 12, 8191)
    # GPT header at LBA 1.
    header = bytearray(92)
    header[0:8] = b"EFI PART"
    struct.pack_into("<Q", header, 72, 2)  # partition entries LBA
    struct.pack_into("<I", header, 80, 128)  # entry count
    struct.pack_into("<I", header, 84, 128)  # entry size
    data[512 : 512 + 92] = header
    # One partition entry at LBA 2.
    entry = bytearray(128)
    entry[0:16] = _gpt_guid_bytes()
    struct.pack_into("<Q", entry, 32, 2048)  # first LBA
    struct.pack_into("<Q", entry, 40, 4095)  # last LBA
    entry[56:56 + 8] = "root".encode("utf-16-le")
    data[1024 : 1024 + 128] = entry
    path = tmp_path / "gpt.img"
    path.write_bytes(bytes(data))
    return path


def test_parse_mbr(tmp_path):
    path = make_mbr_image(tmp_path)
    parts = parse_mbr(path.read_bytes())
    assert len(parts) == 1
    assert parts[0]["type"] == 0x0C
    assert parts[0]["type_name"] == "FAT32"
    assert parts[0]["offset"] == 2048 * 512
    assert parts[0]["size"] == 4096 * 512
    assert parts[0]["bootable"] is True


def test_parse_mbr_no_signature():
    assert parse_mbr(b"\x00" * 1024) == []


def test_parse_gpt(tmp_path):
    path = make_gpt_image(tmp_path)
    parts = parse_gpt(path.read_bytes())
    assert len(parts) == 1
    assert parts[0]["type_name"] == "Linux filesystem"
    assert parts[0]["name"] == "root"
    assert parts[0]["offset"] == 2048 * 512
    assert parts[0]["size"] == 2048 * 512


def test_parse_gpt_no_signature():
    assert parse_gpt(b"\x00" * 4096) == []


def test_parse_partitions_prefers_gpt(tmp_path):
    path = make_gpt_image(tmp_path)
    parts = parse_partitions(path.read_bytes())
    assert parts and parts[0]["type_name"] == "Linux filesystem"


def test_detect_filesystem():
    fat = bytearray(2048)
    fat[82:90] = b"FAT32   "
    assert detect_filesystem(bytes(fat), 0) == "FAT32"
    ntfs = bytearray(2048)
    ntfs[3:11] = b"NTFS    "
    assert detect_filesystem(bytes(ntfs), 0) == "NTFS"
    ext = bytearray(2048)
    ext[1080:1082] = b"\x53\xef"
    assert detect_filesystem(bytes(ext), 0) == "ext2/3/4"
    assert detect_filesystem(b"\x00" * 2048, 0) == "unknown"


def test_analyze_disk_image(tmp_path):
    path = make_mbr_image(tmp_path)
    report = analyze_disk_image(path)
    assert report["kind"] == "disk"
    assert report["size_bytes"] == 4 * 1024 * 1024
    assert len(report["sha256"]) == 64
    assert len(report["partitions"]) == 1
    assert report["partitions"][0]["filesystem"] == "FAT32"
    assert report["secret_scan_limit_mb"] == 16
    assert report["score"] >= 40
    assert EXAMPLE_KEY.decode() not in str(report)
    rules = {f["rule"] for f in report["findings"]}
    assert "aws_access_key" in rules


def test_analyze_disk_image_limit(tmp_path):
    path = make_mbr_image(tmp_path)
    report = analyze_disk_image(path, limit_mb=1)
    assert report["secret_scan_limit_mb"] == 1
    assert report["secret_scan_window_bytes"] == 1024 * 1024


def test_analyze_disk_missing_file():
    with pytest.raises(FileNotFoundError):
        analyze_disk_image("/nonexistent/disk.img")


def test_validate_disk_device():
    assert validate_disk_device("/dev/sdb") == "/dev/sdb"
    with pytest.raises(DiskError):
        validate_disk_device("../etc/passwd")
    with pytest.raises(DiskError):
        validate_disk_device("/tmp/not-a-disk")
    with pytest.raises(DiskError):
        validate_disk_device("")


def test_disk_device_scan_requires_authorized():
    with pytest.raises(DiskError):
        disk_device_scan("/dev/sdb", authorized=False, read_only=True)


def test_disk_device_scan_requires_read_only():
    with pytest.raises(DiskError):
        disk_device_scan("/dev/sdb", authorized=True, read_only=False)
