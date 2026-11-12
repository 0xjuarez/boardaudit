"""Stronger disk analysis tests: SMART parsing, GPT backup header,
partition overlaps, ext superblock checks, and per-partition hashes."""

import struct

from boardaudit.disk import (
    analyze_disk_image,
    check_ext_superblock,
    check_gpt_backup,
    detect_partition_overlaps,
    parse_smartctl_output,
)

from test_disk import make_gpt_image, make_mbr_image

SMART_SAMPLE = """smartctl 7.3
=== START OF READ SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED
ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0
194 Temperature_Celsius     0x0022   064   050   000    Old_age   Always       -       36
"""


def test_parse_smartctl_output():
    parsed = parse_smartctl_output(SMART_SAMPLE)
    assert parsed["available"] is True
    assert parsed["health"] == "PASSED"
    assert parsed["temperature_c"] == 36
    assert parsed["attributes"]["Reallocated_Sector_Ct"] == "0"
    assert parse_smartctl_output("") == {"available": False}
    assert parse_smartctl_output("nothing here") == {"available": False}


def test_detect_partition_overlaps():
    partitions = [
        {"name": "p1", "offset": 0, "size": 1024},
        {"name": "p2", "offset": 512, "size": 1024},
        {"name": "p3", "offset": 4096, "size": 8192},
    ]
    result = detect_partition_overlaps(partitions, 4096)
    assert len(result["overlaps"]) == 1
    assert result["overlaps"][0]["partition_a"] == "p1"
    assert result["overlaps"][0]["partition_b"] == "p2"
    assert len(result["out_of_bounds"]) == 1
    assert result["out_of_bounds"][0]["partition"] == "p3"
    clean = detect_partition_overlaps(
        [{"name": "p1", "offset": 0, "size": 1024}], 4096
    )
    assert clean["overlaps"] == [] and clean["out_of_bounds"] == []


def test_gpt_backup_header_present_and_missing(tmp_path):
    path = make_gpt_image(tmp_path)
    size = path.stat().st_size
    # No backup header yet.
    result = check_gpt_backup(path, size, 128)
    assert result["present"] is False
    # Write a backup header in the last sector.
    data = bytearray(path.read_bytes())
    backup = bytearray(92)
    backup[0:8] = b"EFI PART"
    struct.pack_into("<I", backup, 80, 128)
    data[size - 512 : size - 512 + 92] = backup
    path.write_bytes(bytes(data))
    result = check_gpt_backup(path, size, 128)
    assert result["present"] is True
    assert result["entry_count"] == 128
    assert result["matches_primary"] is True
    assert check_gpt_backup(path, size, 64)["matches_primary"] is False


def test_disk_analyze_reports_backup_and_overlaps(tmp_path):
    path = make_gpt_image(tmp_path)
    size = path.stat().st_size
    data = bytearray(path.read_bytes())
    backup = bytearray(92)
    backup[0:8] = b"EFI PART"
    struct.pack_into("<I", backup, 80, 128)
    data[size - 512 : size - 512 + 92] = backup
    path.write_bytes(bytes(data))
    report = analyze_disk_image(path)
    assert report["gpt_backup"]["present"] is True
    assert report["gpt_backup"]["matches_primary"] is True
    assert report["partition_overlaps"]["overlaps"] == []
    assert report["partition_overlaps"]["out_of_bounds"] == []


def test_check_ext_superblock():
    data = bytearray(4096)
    # ext superblock at partition offset + 1024; magic at +56.
    data[1024 + 56 : 1024 + 58] = b"\x53\xef"
    struct.pack_into("<I", data, 1024 + 0, 1000)  # inodes
    struct.pack_into("<I", data, 1024 + 24, 2)  # log block size -> 4096
    struct.pack_into("<H", data, 1024 + 58, 1)  # state clean
    struct.pack_into("<I", data, 1024 + 96, 0x4)  # has journal
    info = check_ext_superblock(bytes(data), 0)
    assert info is not None
    assert info["inodes"] == 1000
    assert info["block_size"] == 4096
    assert info["state"] == "clean"
    assert info["has_journal"] is True
    assert check_ext_superblock(b"\x00" * 4096, 0) is None


def test_disk_analyze_hash_all(tmp_path):
    path = make_mbr_image(tmp_path)
    report = analyze_disk_image(path, hash_all=True)
    assert len(report["partition_hashes"]) == 1
    entry = report["partition_hashes"][0]
    assert len(entry["sha256"]) == 64
    assert entry["sha256_scope"] == "first 4 MiB of the partition"
    report2 = analyze_disk_image(path, hash_all=False)
    assert report2["partition_hashes"] == []
