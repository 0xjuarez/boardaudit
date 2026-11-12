"""Pure-Python firmware analysis.

No shell commands, no eval/exec. Secrets are never written in full:
findings carry only a pattern type, a count, and a redacted preview.
Each finding also carries a rule id, a severity, and remediation
text, so a report is usable as a triage checklist.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .deep import detect_certificates, list_archive_entries, parse_elf
from .profiles import Profile, resolve_profile_arg

MAX_FIRMWARE_SIZE = 64 * 1024 * 1024  # 64 MiB

# ESP32 partition table: 32-byte entries at offset 0x8000.
ESP_PARTITION_TABLE_OFFSET = 0x8000
ESP_PARTITION_MAGIC = b"\xaa\x50"


@dataclass(frozen=True)
class SecretRule:
    name: str
    pattern: re.Pattern[str]
    weight: int
    description: str
    remediation: str = ""


SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "aws_access_key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        40,
        "AWS access key ID pattern",
        "Rotate the key, remove it from the firmware image, and move "
        "credentials to a provisioned secret store. Do not ship keys "
        "in firmware.",
    ),
    SecretRule(
        "aws_session_key",
        re.compile(r"ASIA[0-9A-Z]{16}"),
        40,
        "AWS session key pattern",
        "Rotate the key, remove it from the firmware image, and move "
        "credentials to a provisioned secret store. Do not ship keys "
        "in firmware.",
    ),
    SecretRule(
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        25,
        "Embedded private key header",
        "Remove the private key from the image. Provision keys per "
        "device at manufacturing time and store them in protected "
        "storage.",
    ),
    SecretRule(
        "certificate",
        re.compile(r"-----BEGIN CERTIFICATE-----"),
        15,
        "Embedded certificate header",
        "Check whether the certificate is a public trust anchor or a "
        "private credential. Replace embedded private material with "
        "per-device provisioning.",
    ),
    SecretRule(
        "generic_secret_assignment",
        re.compile(
            r"(?i)(?:api[_-]?key|secret|token|password|passwd)\s*=\s*['\"]?[^\s'\";]{8,}"
        ),
        30,
        "Secret or credential assigned in a string",
        "Remove the assigned value from the image, rotate it, and "
        "load it from a provisioned secret store at runtime.",
    ),
    SecretRule(
        "default_credential",
        re.compile(
            r"(?i)\b(?:admin|root|user)\s*[:=]\s*(?:admin|root|password|123456|1234)\b"
        ),
        30,
        "Default credential pattern (well-known username and password)",
        "Replace default credentials with a unique per-device "
        "password set at first setup, and force a password change "
        "on first login.",
    ),
    SecretRule(
        "telnet_service",
        re.compile(r"(?i)\btelnet\b"),
        10,
        "Telnet service string (cleartext remote access)",
        "Disable Telnet. Use SSH with key authentication where "
        "remote access is required.",
    ),
    SecretRule(
        "ssh_service",
        re.compile(r"(?i)\b(?:ssh|dropbear|openssh)\b"),
        5,
        "SSH service string",
        "Confirm SSH is required, disable password authentication, "
        "and use key authentication with a unique per-device key.",
    ),
    SecretRule(
        "wifi_credential",
        re.compile(r"(?i)\b(?:ssid|wifi)\b\s*[:=]\s*[^\s'\";]{3,}"),
        5,
        "Wi-Fi identifier or credential string",
        "Do not ship Wi-Fi credentials in firmware. Provision "
        "network credentials per device at setup time.",
    ),
    SecretRule(
        "http_endpoint",
        re.compile(r"https?://[^\s'\"<>]+"),
        5,
        "HTTP(S) endpoint string",
        "Review the endpoint: confirm it uses HTTPS, check what "
        "data it receives, and remove unused update or telemetry "
        "endpoints.",
    ),
)


def severity_for_weight(weight: int) -> str:
    """Map a rule weight to a finding severity."""
    if weight >= 40:
        return "critical"
    if weight >= 25:
        return "high"
    if weight >= 10:
        return "medium"
    return "low"


def redact(value: str) -> str:
    """Return a redacted preview: first 4 characters, rest replaced by '*'.

    Values of 4 characters or fewer become '****'. The full value is
    never returned.
    """
    if not value:
        return "****"
    if len(value) <= 4:
        return "****"
    return value[:4] + "*" * (len(value) - 4)


def redact_assignment(text: str) -> str:
    """Redact the value part of a KEY=value string, keeping the key name."""
    match = re.search(r"=", text)
    if match is None:
        return redact(text)
    key = text[: match.start()]
    value = text[match.start() + 1 :].strip().strip("'\"")
    if not value:
        return key + "=****"
    return key + "=" + "*" * min(len(value), 16)


def extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract printable ASCII strings of at least min_length characters."""
    if min_length < 1:
        raise ValueError("min_length must be at least 1")
    strings: list[str] = []
    current: list[str] = []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []
    if len(current) >= min_length:
        strings.append("".join(current))
    return strings


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte, 0.0 for empty input."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    result = 0.0
    for count in counts.values():
        p = count / total
        result -= p * math.log2(p)
    return round(result, 4)


def entropy_by_section(
    data: bytes, section_size: int = 65536
) -> list[dict[str, object]]:
    """Shannon entropy per section, so packed or encrypted regions stand out.

    Each entry has offset, size, and entropy in bits per byte.
    """
    if section_size < 1:
        raise ValueError("section_size must be at least 1")
    sections: list[dict[str, object]] = []
    for offset in range(0, len(data), section_size):
        chunk = data[offset : offset + section_size]
        sections.append(
            {
                "offset": offset,
                "size": len(chunk),
                "entropy_bits_per_byte": entropy(chunk),
            }
        )
    return sections


# Magic bytes for embedded blobs, checked in file order. "tar" is
# handled separately because its magic sits at offset 257 in a block.
EMBEDDED_MAGICS: tuple[tuple[str, bytes], ...] = (
    ("uimage", b"\x27\x05\x19\x56"),
    ("trx", b"HDR0"),
    ("squashfs", b"hsqs"),
    ("jffs2", b"\x85\x19"),
    ("ubifs", b"UBI#"),
    ("gzip", b"\x1f\x8b"),
    ("lzma", b"\x5d\x00\x00"),
    ("zip", b"PK\x03\x04"),
    ("elf", b"\x7fELF"),
)


def detect_embedded_formats(
    data: bytes, max_per_format: int = 20
) -> list[dict[str, object]]:
    """Detect embedded blobs by magic bytes, returning format and offset.

    Only the first max_per_format occurrences of each format are
    reported, so a large image does not produce an unbounded list.
    """
    found: list[dict[str, object]] = []
    for name, magic in EMBEDDED_MAGICS:
        start = 0
        count = 0
        while count < max_per_format:
            offset = data.find(magic, start)
            if offset < 0:
                break
            found.append({"format": name, "offset": offset})
            count += 1
            start = offset + 1
    # tar: "ustar" at offset 257 inside a 512-byte block.
    start = 0
    count = 0
    while count < max_per_format:
        offset = data.find(b"ustar", start)
        if offset < 0:
            break
        if offset >= 257 and (offset - 257) % 512 == 0:
            found.append({"format": "tar", "offset": offset - 257})
            count += 1
        start = offset + 1
    found.sort(key=lambda item: int(item["offset"]))
    return found


def duplicate_strings(
    strings: list[str], min_count: int = 3, limit: int = 10
) -> list[dict[str, object]]:
    """Strings that repeat at least min_count times, most frequent first.

    Strings matching a secret rule are excluded, and values are
    truncated to 80 characters.
    """
    counts = Counter(strings)
    results: list[dict[str, object]] = []
    for text, count in counts.most_common(limit * 2):
        if count < min_count:
            break
        if any(rule.pattern.search(text) for rule in SECRET_RULES):
            continue
        results.append({"string": text[:80], "count": count})
        if len(results) >= limit:
            break
    return results


def parse_esp_partitions(
    data: bytes, offset: int = ESP_PARTITION_TABLE_OFFSET
) -> list[dict[str, object]]:
    """Parse an ESP partition table at offset when the magic is present.

    Entry layout (32 bytes): magic (2), type (1), subtype (1),
    offset (4, little-endian), size (4, little-endian), label (16),
    flags (4). Returns an empty list when no valid table is present.
    The offset defaults to 0x8000 and can be overridden from a
    profile's ``partition_table_offset`` extra field.
    """
    if offset < 0 or len(data) < offset + 32:
        return []
    partitions: list[dict[str, object]] = []
    for index in range(16):
        entry = data[offset + index * 32 : offset + (index + 1) * 32]
        if len(entry) < 32:
            break
        if entry[0:2] != ESP_PARTITION_MAGIC:
            break
        if entry[0:2] == b"\xff\xff":
            break
        part_type = entry[2]
        part_subtype = entry[3]
        part_offset = int.from_bytes(entry[4:8], "little")
        part_size = int.from_bytes(entry[8:12], "little")
        label = entry[12:28].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        partitions.append(
            {
                "name": label,
                "type": part_type,
                "subtype": part_subtype,
                "offset": part_offset,
                "size": part_size,
            }
        )
    return partitions


def _safe_sample_strings(strings: list[str], limit: int = 20) -> list[str]:
    """Return short, non-secret strings for display in a report.

    Any string matching a secret rule is excluded. Values are truncated
    to 80 characters.
    """
    safe: list[str] = []
    for text in strings:
        if any(rule.pattern.search(text) for rule in SECRET_RULES):
            continue
        safe.append(text[:80])
        if len(safe) >= limit:
            break
    return safe


def detect_secrets(strings: list[str]) -> list[dict[str, object]]:
    """Detect secret patterns in extracted strings, with redaction.

    The returned findings never contain a full secret value. Each
    finding carries rule, rule_id, description, weight, severity,
    remediation, count, and a redacted preview.
    """
    findings: list[dict[str, object]] = []
    for rule in SECRET_RULES:
        count = 0
        preview = ""
        for text in strings:
            for match in rule.pattern.finditer(text):
                count += 1
                if not preview:
                    matched = match.group(0)
                    if rule.name == "generic_secret_assignment":
                        preview = redact_assignment(matched)
                    elif rule.name in ("private_key", "certificate"):
                        preview = matched  # header only, no key material
                    else:
                        preview = redact(matched)
        if count:
            findings.append(
                {
                    "rule": rule.name,
                    "rule_id": rule.name,
                    "description": rule.description,
                    "weight": rule.weight,
                    "severity": severity_for_weight(rule.weight),
                    "remediation": rule.remediation,
                    "count": count,
                    "preview": preview,
                }
            )
    return findings


def risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _stream_hash_entropy(path: Path) -> tuple[str, float]:
    """SHA-256 and Shannon entropy of a file, streamed in 1 MiB chunks.

    The whole file is never loaded into memory.
    """
    digest = hashlib.sha256()
    counts = [0] * 256
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            for byte in chunk:
                counts[byte] += 1
    if total == 0:
        return digest.hexdigest(), 0.0
    result = 0.0
    for count in counts:
        if count:
            p = count / total
            result -= p * math.log2(p)
    return digest.hexdigest(), round(result, 4)


def analyze_firmware(
    path: str | Path,
    limit_mb: int | None = None,
    profile: "Profile | str | Path | None" = None,
    rules: list | None = None,
) -> dict[str, object]:
    """Analyze a firmware file and return a report dictionary.

    The dictionary contains no full secret values. When limit_mb is
    given, string extraction, secret detection, embedded-format
    detection, and per-section entropy cover only the first
    limit_mb megabytes; the SHA-256, size, and whole-file entropy
    always cover the whole file, streamed in chunks. When a profile
    is given (a Profile, a profile id, or a profile file path), its
    partition-table offset and filesystem hints are used and the
    report records which profile was used; otherwise auto-detection
    is used. Custom rules are applied in addition to the built-in
    secret rules.
    """
    firmware_path = Path(path)
    if not firmware_path.is_file():
        raise FileNotFoundError(f"firmware file not found: {firmware_path}")
    size = firmware_path.stat().st_size
    if size > MAX_FIRMWARE_SIZE:
        raise ValueError(
            f"firmware file too large: {size} bytes (limit {MAX_FIRMWARE_SIZE})"
        )
    if limit_mb is not None and limit_mb < 1:
        raise ValueError("limit_mb must be at least 1")
    resolved_profile: Profile | None = None
    if profile is not None:
        if isinstance(profile, Profile):
            resolved_profile = profile
        else:
            resolved_profile = resolve_profile_arg(profile)
    partition_offset = ESP_PARTITION_TABLE_OFFSET
    if resolved_profile is not None:
        extra_offset = resolved_profile.extra.get("partition_table_offset")
        if isinstance(extra_offset, int) and extra_offset >= 0:
            partition_offset = extra_offset
    window_bytes = size
    if limit_mb is not None:
        window_bytes = min(size, limit_mb * 1024 * 1024)
    sha256, whole_entropy = _stream_hash_entropy(firmware_path)
    with firmware_path.open("rb") as handle:
        window = handle.read(window_bytes)
    strings = extract_strings(window)
    findings = detect_secrets(strings)
    if rules:
        from .rules import apply_custom_rules

        seen = {f["rule"] for f in findings}
        for finding in apply_custom_rules(strings, rules):
            if finding["rule"] not in seen:
                findings.append(finding)
    score = min(100, sum(int(f["weight"]) * int(f["count"]) for f in findings))
    elf_binaries: list[dict[str, object]] = []
    for entry in detect_embedded_formats(window):
        if entry["format"] == "elf":
            parsed = parse_elf(window, int(entry["offset"]))
            if parsed is not None:
                elf_binaries.append(parsed)
    return {
        "tool": "boardaudit",
        "file": firmware_path.name,
        "size_bytes": size,
        "sha256": sha256,
        "entropy_bits_per_byte": whole_entropy,
        "entropy_sections": entropy_by_section(window),
        "embedded_formats": detect_embedded_formats(window),
        "elf_binaries": elf_binaries,
        "archive_entries": list_archive_entries(window),
        "certificates": detect_certificates(window),
        "duplicate_strings": duplicate_strings(strings),
        "analysis_limit_mb": limit_mb,
        "analysis_window_bytes": len(window),
        "string_count": len(strings),
        "sample_strings": _safe_sample_strings(strings),
        "partitions": parse_esp_partitions(window, offset=partition_offset),
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
