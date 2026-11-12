"""Disk / hard drive support: image analysis, inventory, read-only scans.

Authorized use only. Analyzing a disk image file is safe and
offline. Scanning a live block device is read-only (O_RDONLY) and
requires --authorized; the system/root disk and any mounted
read-write device are refused unless --allow-mounted is passed.
boardaudit never writes to a disk, never wipes, never formats, and
never recovers deleted files by writing. Imaging a disk to a file
first and analyzing the image is the recommended workflow, because
reading a live disk can change access times.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .analysis import (
    detect_secrets,
    duplicate_strings,
    entropy,
    entropy_by_section,
    extract_strings,
    risk_level,
)
from .inventory import _run

SECTOR_SIZE = 512
DEFAULT_SECRET_SCAN_MB = 16
MAX_DISK_IMAGE_SIZE = 256 * 1024 * 1024 * 1024  # 256 GiB, streamed


class DiskError(Exception):
    """Raised when a disk operation cannot proceed safely."""


# --- Partition tables ------------------------------------------------------

MBR_PARTITION_TYPES: dict[int, str] = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16",
    0x06: "FAT16",
    0x07: "NTFS / HPFS",
    0x0B: "FAT32",
    0x0C: "FAT32",
    0x0E: "FAT16",
    0x0F: "Extended",
    0x82: "Linux swap",
    0x83: "Linux filesystem",
    0x85: "Linux extended",
    0xEE: "GPT protective",
    0xEF: "EFI System",
}

GPT_TYPE_GUIDS: dict[str, str] = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Microsoft basic data",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux swap",
    "933ac7e1-2eb4-4f13-b844-0e14e2aef915": "Linux home",
    "21686148-6449-6e6f-744e-656564454649": "BIOS boot",
}


def _guid_string(raw: bytes) -> str:
    """Format a 16-byte GPT GUID (mixed-endian) as a lowercase string."""
    if len(raw) != 16:
        return ""
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    d4 = raw[8:10]
    d5 = raw[10:16]
    return (
        f"{d1:08x}-{d2:04x}-{d3:04x}-{d4.hex()}-{d5.hex()}"
    )


def parse_mbr(data: bytes) -> list[dict[str, object]]:
    """Parse an MBR partition table from the first 512 bytes.

    Returns an empty list when the 0x55AA signature is absent.
    """
    if len(data) < 512 or data[510:512] != b"\x55\xaa":
        return []
    partitions: list[dict[str, object]] = []
    for index in range(4):
        entry = data[446 + index * 16 : 446 + (index + 1) * 16]
        part_type = entry[4]
        if part_type == 0x00:
            continue
        start_lba = int.from_bytes(entry[8:12], "little")
        sectors = int.from_bytes(entry[12:16], "little")
        partitions.append(
            {
                "index": index,
                "name": f"partition{index + 1}",
                "type": part_type,
                "type_name": MBR_PARTITION_TYPES.get(part_type, "Unknown"),
                "bootable": bool(entry[0] & 0x80),
                "offset": start_lba * SECTOR_SIZE,
                "size": sectors * SECTOR_SIZE,
                "start_lba": start_lba,
                "sectors": sectors,
            }
        )
    return partitions


def parse_gpt(data: bytes) -> list[dict[str, object]]:
    """Parse a GPT partition table.

    Reads the header at LBA 1 (offset 512) and the entries at LBA 2
    (offset 1024). Returns an empty list when the 'EFI PART'
    signature is absent.
    """
    if len(data) < 512 + 92 or data[512:520] != b"EFI PART":
        return []
    header = data[512:512 + 92]
    entry_lba = struct.unpack_from("<Q", header, 72)[0]
    entry_count = struct.unpack_from("<I", header, 80)[0]
    entry_size = struct.unpack_from("<I", header, 84)[0]
    if entry_size < 128 or entry_count == 0 or entry_count > 1024:
        return []
    entries_offset = entry_lba * SECTOR_SIZE
    partitions: list[dict[str, object]] = []
    for index in range(min(entry_count, 128)):
        start = entries_offset + index * entry_size
        entry = data[start : start + 128]
        if len(entry) < 128:
            break
        type_guid = _guid_string(entry[0:16])
        if type_guid == "00000000-0000-0000-0000-000000000000":
            continue
        first_lba = int.from_bytes(entry[32:40], "little")
        last_lba = int.from_bytes(entry[40:48], "little")
        # The name field is 72 bytes of UTF-16LE. Decode the whole
        # field and strip trailing NULs; splitting on a double NUL
        # byte pair would cut a name mid-character, because every
        # ASCII character already ends in a NUL byte.
        name = entry[56:128].decode("utf-16-le", errors="replace").rstrip("\x00")
        partitions.append(
            {
                "index": index,
                "name": name or f"partition{index + 1}",
                "type": type_guid,
                "type_name": GPT_TYPE_GUIDS.get(type_guid, "Unknown"),
                "offset": first_lba * SECTOR_SIZE,
                "size": max(0, (last_lba - first_lba + 1) * SECTOR_SIZE),
                "first_lba": first_lba,
                "last_lba": last_lba,
            }
        )
    return partitions


def parse_partitions(data: bytes) -> list[dict[str, object]]:
    """Parse GPT when present, otherwise MBR."""
    gpt = parse_gpt(data)
    if gpt:
        return gpt
    return parse_mbr(data)


def detect_partition_overlaps(
    partitions: list[dict[str, object]], image_size: int | None
) -> dict[str, object]:
    """Check partitions for overlaps and for running past the image.

    Returns {"overlaps": [...], "out_of_bounds": [...]} where each
    overlap names the two partitions and the overlapping byte range.
    When image_size is None, the out-of-bounds check is skipped
    (used for live-device scans, where the total size is unknown).
    """
    ordered = sorted(partitions, key=lambda p: int(p["offset"]))
    overlaps: list[dict[str, object]] = []
    out_of_bounds: list[dict[str, object]] = []
    previous_end = 0
    previous_name = ""
    for part in ordered:
        offset = int(part["offset"])
        size = int(part["size"])
        name = str(part.get("name", ""))
        if image_size is not None and offset + size > image_size:
            out_of_bounds.append(
                {
                    "partition": name,
                    "offset": offset,
                    "size": size,
                    "image_size": image_size,
                }
            )
        if offset < previous_end and previous_name:
            overlaps.append(
                {
                    "partition_a": previous_name,
                    "partition_b": name,
                    "overlap_start": offset,
                    "overlap_end": min(previous_end, offset + size),
                }
            )
        if offset + size > previous_end:
            previous_end = offset + size
            previous_name = name
    return {"overlaps": overlaps, "out_of_bounds": out_of_bounds}


def check_gpt_backup(
    path: str | Path, image_size: int, primary_entry_count: int
) -> dict[str, object]:
    """Check the GPT backup header in the last sector of the image.

    Returns whether the backup header is present, whether its
    partition-entry count matches the primary header, and the
    backup entry count. A missing or mismatched backup header is
    a sign of a truncated or edited image.
    """
    image_path = Path(path)
    result: dict[str, object] = {
        "present": False,
        "entry_count": None,
        "matches_primary": False,
    }
    if image_size < 1024:
        return result
    try:
        with image_path.open("rb") as handle:
            handle.seek(image_size - 512)
            last = handle.read(512)
    except OSError:
        return result
    if len(last) < 92 or last[0:8] != b"EFI PART":
        return result
    entry_count = struct.unpack_from("<I", last, 80)[0]
    result["present"] = True
    result["entry_count"] = entry_count
    result["matches_primary"] = entry_count == primary_entry_count
    return result


def check_ext_superblock(data: bytes, offset: int) -> dict[str, object] | None:
    """Check an ext2/3/4 superblock at a partition offset.

    Returns inode count, block size, state (clean or errors), and
    whether a journal is present, or None when the magic is absent.
    """
    base = offset + 1024
    if offset < 0 or len(data) < base + 102:
        return None
    if data[base + 56 : base + 58] != b"\x53\xef":
        return None
    inodes = int.from_bytes(data[base + 0 : base + 4], "little")
    log_block_size = int.from_bytes(data[base + 24 : base + 28], "little")
    state = int.from_bytes(data[base + 58 : base + 60], "little")
    feature_incompat = int.from_bytes(data[base + 96 : base + 100], "little")
    return {
        "inodes": inodes,
        "block_size": 1024 << log_block_size,
        "state": "clean" if state == 1 else "errors",
        "state_code": state,
        "has_journal": bool(feature_incompat & 0x4),
    }


def parse_smartctl_output(text: str) -> dict[str, object]:
    """Parse smartctl -H -A output (read-only health summary).

    Returns overall health, temperature when reported, and the
    SMART attributes as name -> raw value. Unparseable output
    returns {"available": False}.
    """
    if not text or "SMART" not in text:
        return {"available": False}
    health = ""
    for line in text.splitlines():
        if "SMART overall-health self-assessment test result" in line:
            health = line.split(":", 1)[1].strip() if ":" in line else ""
            break
    attributes: dict[str, object] = {}
    temperature: int | None = None
    in_table = False
    for line in text.splitlines():
        if line.strip().startswith("ID#"):
            in_table = True
            continue
        if in_table:
            parts = line.split()
            if len(parts) >= 10 and parts[0].isdigit():
                name = parts[1]
                raw_value = parts[-1]
                attributes[name] = raw_value
                if name in ("Temperature_Celsius", "Airflow_Temperature_Cel"):
                    try:
                        temperature = int(raw_value)
                    except ValueError:
                        pass
    return {
        "available": True,
        "health": health or "unknown",
        "temperature_c": temperature,
        "attributes": attributes,
    }


def smart_summary(device: str) -> dict[str, object]:
    """Read-only SMART health summary for a device, when smartctl exists.

    Runs only ``smartctl -H -A`` (health and attributes). It never
    runs a self-test or any destructive command.
    """
    output = _run(["smartctl", "-H", "-A", device])
    if not output:
        return {"available": False}
    return parse_smartctl_output(output)


# --- Filesystem detection --------------------------------------------------

def detect_filesystem(data: bytes, offset: int = 0) -> str:
    """Guess a filesystem at offset from magic bytes, or 'unknown'."""
    if offset < 0 or len(data) < offset + 8:
        return "unknown"
    chunk = data[offset : offset + 2048]
    if len(chunk) >= 3 and chunk[3:11] == b"NTFS    ":
        return "NTFS"
    if len(chunk) >= 11 and chunk[3:11] == b"EXFAT   ":
        return "exFAT"
    if len(chunk) >= 90 and chunk[82:90] == b"FAT32   ":
        return "FAT32"
    if len(chunk) >= 62 and chunk[54:62] == b"FAT16   ":
        return "FAT16"
    if len(chunk) >= 62 and chunk[54:62] == b"FAT12   ":
        return "FAT12"
    # ext2/3/4 superblock magic 0x53EF at offset 1080 from the
    # partition start.
    if len(data) >= offset + 1082:
        if data[offset + 1080 : offset + 1082] == b"\x53\xef":
            return "ext2/3/4"
    return "unknown"


# --- Disk image analysis ---------------------------------------------------

def _streamed_sha256(path: Path) -> str:
    """SHA-256 of a file, streamed in 1 MiB chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _streamed_entropy(path: Path) -> float:
    """Shannon entropy over the whole file, streamed, low memory."""
    counts = [0] * 256
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            for byte in chunk:
                counts[byte] += 1
    if total == 0:
        return 0.0
    result = 0.0
    for count in counts:
        if count:
            p = count / total
            result -= p * math.log2(p)
    return round(result, 4)


def analyze_disk_image(
    path: str | Path,
    limit_mb: int | None = None,
    profile: "object | str | Path | None" = None,
    rules: list | None = None,
    hash_all: bool = False,
) -> dict[str, object]:
    """Analyze a disk image file and return a report dictionary.

    The image is never written to. SHA-256 and entropy are computed
    over the whole file, streamed. Secret-pattern detection covers
    only the first limit_mb megabytes (default 16 MiB); the limit
    is recorded in the report. Findings never contain a full secret.
    With hash_all, each partition is also hashed separately over
    its first 4 MiB window (the scope is recorded in the report).
    A profile (id, file, or Profile) is recorded when used.
    """
    from .deep import detect_certificates, list_archive_entries
    from .profiles import Profile, resolve_profile_arg

    image_path = Path(path)
    if not image_path.is_file():
        raise FileNotFoundError(f"disk image not found: {image_path}")
    size = image_path.stat().st_size
    if size > MAX_DISK_IMAGE_SIZE:
        raise ValueError(
            f"disk image too large: {size} bytes (limit {MAX_DISK_IMAGE_SIZE})"
        )
    resolved_profile: Profile | None = None
    if profile is not None:
        if isinstance(profile, Profile):
            resolved_profile = profile
        else:
            resolved_profile = resolve_profile_arg(profile)
    scan_mb = DEFAULT_SECRET_SCAN_MB if limit_mb is None else limit_mb
    if scan_mb < 1:
        raise ValueError("limit_mb must be at least 1")
    window_bytes = scan_mb * 1024 * 1024
    with image_path.open("rb") as handle:
        head = handle.read(2 * 1024 * 1024)
        window = head[:window_bytes]
        if len(window) < window_bytes:
            window += handle.read(window_bytes - len(window))
    partitions = parse_partitions(head)
    for partition in partitions:
        offset = int(partition["offset"])
        partition["filesystem"] = detect_filesystem(head, offset)
        if partition["filesystem"] == "ext2/3/4":
            superblock = check_ext_superblock(head, offset)
            if superblock is not None:
                partition["ext_superblock"] = superblock
    partition_hashes: list[dict[str, object]] = []
    if hash_all:
        for partition in partitions:
            offset = int(partition["offset"])
            part_size = int(partition["size"])
            hash_window = min(part_size, 4 * 1024 * 1024)
            digest = hashlib.sha256()
            with image_path.open("rb") as handle:
                handle.seek(offset)
                remaining = hash_window
                while remaining > 0:
                    chunk = handle.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    digest.update(chunk)
                    remaining -= len(chunk)
            partition_hashes.append(
                {
                    "partition": partition.get("name"),
                    "offset": offset,
                    "size": part_size,
                    "sha256": digest.hexdigest(),
                    "sha256_scope": "first 4 MiB of the partition",
                }
            )
    is_gpt = head[512:520] == b"EFI PART"
    primary_entry_count = 0
    if is_gpt:
        primary_entry_count = struct.unpack_from("<I", head, 512 + 80)[0]
    gpt_backup = (
        check_gpt_backup(image_path, size, primary_entry_count)
        if is_gpt
        else {"present": False, "entry_count": None, "matches_primary": False}
    )
    strings = extract_strings(window)
    findings = detect_secrets(strings)
    if rules:
        from .rules import apply_custom_rules

        seen = {f["rule"] for f in findings}
        for finding in apply_custom_rules(strings, rules):
            if finding["rule"] not in seen:
                findings.append(finding)
    score = min(100, sum(int(f["weight"]) * int(f["count"]) for f in findings))
    return {
        "tool": "boardaudit",
        "kind": "disk",
        "file": image_path.name,
        "size_bytes": size,
        "sha256": _streamed_sha256(image_path),
        "entropy_bits_per_byte": _streamed_entropy(image_path),
        "entropy_sections": entropy_by_section(window[: 64 * 1024 * 16]),
        "partitions": partitions,
        "partition_overlaps": detect_partition_overlaps(partitions, size),
        "gpt_backup": gpt_backup,
        "partition_hashes": partition_hashes,
        "elf_binaries": [],
        "archive_entries": list_archive_entries(window),
        "certificates": detect_certificates(window),
        "duplicate_strings": duplicate_strings(strings),
        "secret_scan_limit_mb": scan_mb,
        "secret_scan_window_bytes": len(window),
        "string_count": len(strings),
        "profile_used": resolved_profile.profile_id if resolved_profile else None,
        "profile_kind": resolved_profile.kind if resolved_profile else None,
        "profile_name": resolved_profile.name if resolved_profile else None,
        "custom_rules_applied": len(rules) if rules else 0,
        "findings": findings,
        "score": score,
        "risk_level": risk_level(score),
        "rules": [
            {"rule": f["rule"], "weight": f["weight"], "count": f["count"]}
            for f in findings
        ],
    }


# --- Disk inventory --------------------------------------------------------

@dataclass
class DiskDevice:
    device: str
    model: str
    size_bytes: int
    disk_type: str
    mounted: bool
    mount_points: list[str]


def list_disk_devices() -> list[dict[str, object]]:
    """List block devices, read-only inventory.

    Linux uses lsblk --json, macOS uses diskutil list, Windows uses
    Get-Disk. Missing tools return an empty list, never an install.
    """
    system = platform.system()
    if system == "Linux":
        output = _run(["lsblk", "--json", "--bytes", "--output", "NAME,MODEL,SIZE,TYPE,MOUNTPOINT"])
        if not output:
            return []
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []
        devices: list[dict[str, object]] = []
        for entry in data.get("blockdevices", []):
            if entry.get("type") != "disk":
                continue
            mount_points: list[str] = []
            for child in entry.get("children", []) or []:
                if child.get("mountpoint"):
                    mount_points.append(str(child["mountpoint"]))
            devices.append(
                {
                    "device": f"/dev/{entry.get('name', '')}",
                    "model": str(entry.get("model") or ""),
                    "size_bytes": int(entry.get("size") or 0),
                    "type": "disk",
                    "mounted": bool(mount_points),
                    "mount_points": mount_points,
                }
            )
        return devices
    if system == "Darwin":
        output = _run(["diskutil", "list"])
        devices = []
        for line in output.splitlines():
            match = re.match(r"\s*/dev/(disk\d+)\s+\(external, physical\):", line)
            if match:
                devices.append(
                    {
                        "device": f"/dev/{match.group(1)}",
                        "model": "",
                        "size_bytes": 0,
                        "type": "disk",
                        "mounted": False,
                        "mount_points": [],
                    }
                )
        return devices
    if system == "Windows":
        output = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-Disk | Select-Object Number, FriendlyName, Size, "
                "PartitionStyle | Format-List",
            ]
        )
        devices = []
        current: dict[str, object] = {}
        for line in output.splitlines():
            if ":" not in line:
                if current:
                    devices.append(current)
                    current = {}
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if key == "number":
                current["device"] = f"\\\\.\\PhysicalDrive{value}"
                current["type"] = "disk"
                current["mounted"] = False
                current["mount_points"] = []
            elif key == "friendlyname":
                current["model"] = value
            elif key == "size":
                try:
                    current["size_bytes"] = int(value)
                except ValueError:
                    current["size_bytes"] = 0
        if current:
            devices.append(current)
        return devices
    return []


def disk_inventory() -> dict[str, object]:
    """Return the read-only disk inventory."""
    return {"system": platform.system(), "disks": list_disk_devices()}


# --- Live disk scan safety -------------------------------------------------

def _root_device() -> str:
    """Return the device holding the root filesystem, or ''."""
    if platform.system() == "Linux":
        try:
            with open("/proc/mounts", encoding="utf-8") as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == "/":
                        return parts[0]
        except OSError:
            return ""
    elif platform.system() == "Darwin":
        return "/dev/disk0"
    elif platform.system() == "Windows":
        return "\\\\.\\PhysicalDrive0"
    return ""


def _is_mounted(device: str) -> bool:
    """Return True when the device has a mounted filesystem."""
    if platform.system() == "Linux":
        try:
            with open("/proc/mounts", encoding="utf-8") as handle:
                for line in handle:
                    parts = line.split()
                    if parts and parts[0].startswith(device):
                        return True
        except OSError:
            return False
    return False


def _base_device(device: str) -> str:
    """Strip a partition suffix: /dev/sda1 -> /dev/sda, /dev/nvme0n1p2 -> /dev/nvme0n1."""
    match = re.match(r"^(.*?)(?:p?\d+)$", device)
    if match:
        return match.group(1)
    return device


def validate_disk_device(device: str) -> str:
    """Validate a block-device path. Rejects traversal and non-devices."""
    if not isinstance(device, str) or not device.strip():
        raise DiskError("device must be a non-empty path")
    device = device.strip()
    if ".." in device:
        raise DiskError(f"invalid device path: {device!r}")
    if platform.system() == "Windows":
        if not re.fullmatch(r"\\\\\.\\PhysicalDrive\d+", device):
            raise DiskError(
                f"invalid device path: {device!r}. "
                "Expected \\\\.\\PhysicalDrive<N>"
            )
    else:
        if not device.startswith("/dev/"):
            raise DiskError(
                f"invalid device path: {device!r}. Expected a path under /dev/"
            )
        if re.search(r"\s", device):
            raise DiskError(f"invalid device path: {device!r}")
    return device


def disk_device_scan(
    device: str,
    authorized: bool,
    read_only: bool,
    allow_mounted: bool = False,
    limit_mb: int | None = None,
) -> dict[str, object]:
    """Read-only scan of a live block device.

    The device is opened with O_RDONLY and never written to. The
    system/root disk is always refused. A mounted read-write device
    is refused unless --allow-mounted is passed. --read-only is
    required. Only the first limit_mb megabytes (default 16 MiB)
    are used for secret-pattern detection.
    """
    if not authorized:
        raise DiskError(
            "disk device scan refused: --authorized is required. "
            "Only scan disks you own or are authorized to audit."
        )
    if not read_only:
        raise DiskError(
            "disk device scan refused: --read-only is required. "
            "boardaudit never opens a block device for writing."
        )
    validated = validate_disk_device(device)
    root = _root_device()
    if root and _base_device(validated) == _base_device(root):
        raise DiskError(
            f"disk device scan refused: {validated!r} is the system/root "
            "disk. Image the disk to a file from a live environment "
            "instead, and analyze the image."
        )
    if _is_mounted(validated) and not allow_mounted:
        raise DiskError(
            f"disk device scan refused: {validated!r} is mounted. "
            "Pass --allow-mounted to scan a mounted device, or "
            "unmount it and image it to a file first."
        )
    scan_mb = DEFAULT_SECRET_SCAN_MB if limit_mb is None else limit_mb
    if scan_mb < 1:
        raise DiskError("limit_mb must be at least 1")
    window_bytes = scan_mb * 1024 * 1024
    try:
        fd = os.open(validated, os.O_RDONLY)
    except OSError as exc:
        raise DiskError(f"cannot open device {validated!r} read-only: {exc}") from exc
    try:
        head = os.read(fd, 2 * 1024 * 1024)
        window = head
        if window_bytes > len(head):
            window += os.read(fd, window_bytes - len(head))
        # Streamed SHA-256 would require reading the whole disk; for
        # a live device scan, hash only the window that was read and
        # say so in the report. Full-disk hashing belongs to image
        # analysis, where the size is known and the file is stable.
        digest = hashlib.sha256(window).hexdigest()
    finally:
        os.close(fd)
    partitions = parse_partitions(head)
    for partition in partitions:
        partition["filesystem"] = detect_filesystem(head, int(partition["offset"]))
    strings = extract_strings(window)
    findings = detect_secrets(strings)
    score = min(100, sum(int(f["weight"]) * int(f["count"]) for f in findings))
    return {
        "tool": "boardaudit",
        "kind": "disk-device-scan",
        "device": validated,
        "read_only": True,
        "authorized": True,
        "sha256_window": digest,
        "sha256_scope": "first window only, not the whole disk",
        "entropy_bits_per_byte": entropy(window),
        "entropy_sections": entropy_by_section(window[: 64 * 1024 * 16]),
        "partitions": partitions,
        "partition_overlaps": detect_partition_overlaps(partitions, None),
        "smart": smart_summary(validated),
        "duplicate_strings": duplicate_strings(strings),
        "secret_scan_limit_mb": scan_mb,
        "secret_scan_window_bytes": len(window),
        "string_count": len(strings),
        "findings": findings,
        "score": score,
        "risk_level": risk_level(score),
        "rules": [
            {"rule": f["rule"], "weight": f["weight"], "count": f["count"]}
            for f in findings
        ],
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "note": (
            "Read-only scan of a live block device. Reading a live "
            "disk can change access times. Imaging the disk to a "
            "file first and analyzing the image is the recommended "
            "workflow."
        ),
    }
