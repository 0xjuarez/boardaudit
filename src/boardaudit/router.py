"""Router support: firmware file analysis and read-only LAN inventory.

Authorized use only. Router firmware analysis works on a firmware
file the user already has. The gateway scan is read-only and safe:
one ICMP ping and one TCP connect to ports 80 and 443, with short
timeouts. No login attempts, no brute force, no SNMP writes, no
config download, and no scanning of other hosts. Credential-based
config download is out of scope for this release.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .analysis import (
    MAX_FIRMWARE_SIZE,
    detect_embedded_formats,
    detect_secrets,
    duplicate_strings,
    entropy,
    entropy_by_section,
    extract_strings,
    redact,
    risk_level,
    severity_for_weight,
    sha256_hex,
)
from .deep import detect_certificates, list_archive_entries, parse_elf
from .inventory import _run, list_network_adapters
from .profiles import Profile, list_profiles, resolve_profile_arg


@dataclass(frozen=True)
class RouterProfile:
    profile_id: str
    soc: str
    vendor_family: str
    flash_size: int  # bytes
    filesystem: str
    acquisition_notes: str


def _router_profiles() -> dict[str, RouterProfile]:
    return {
        p.profile_id: RouterProfile(
            profile_id=p.profile_id,
            soc=p.soc or p.name,
            vendor_family=p.vendor_family,
            flash_size=p.flash_size,
            filesystem=p.filesystem,
            acquisition_notes=p.notes,
        )
        for p in list_profiles(kind="router")
    }


ROUTER_PROFILES: dict[str, RouterProfile] = _router_profiles()


def list_router_profiles() -> list[RouterProfile]:
    return [ROUTER_PROFILES[key] for key in sorted(ROUTER_PROFILES)]


def get_router_profile(profile_id: str) -> RouterProfile:
    profile = _router_profiles().get(profile_id.strip().lower())
    if profile is None:
        known = ", ".join(sorted(_router_profiles()))
        raise ValueError(f"unknown router profile: {profile_id!r}. Known: {known}")
    return profile


# --- Firmware format detection -------------------------------------------

def detect_router_formats(data: bytes) -> list[dict[str, object]]:
    """Detect router firmware formats by magic bytes.

    Reuses the shared embedded-format detector and adds TRX and
    uImage, which that detector already covers. Returns format and
    offset, sorted by offset.
    """
    return detect_embedded_formats(data)


def parse_uimage_header(data: bytes, offset: int = 0) -> dict[str, object] | None:
    """Parse a uImage header at offset, or return None if not present.

    uImage header (64 bytes, big-endian): magic, header CRC, time,
    size, load address, entry point, data CRC, OS, architecture,
    type, compression, name (32 bytes).
    """
    if offset < 0 or len(data) < offset + 64:
        return None
    if data[offset : offset + 4] != b"\x27\x05\x19\x56":
        return None
    fields = struct.unpack_from(">7I4B32s", data, offset)
    name = fields[11].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    return {
        "format": "uimage",
        "offset": offset,
        "header_crc": fields[1],
        "timestamp": fields[2],
        "size": fields[3],
        "load_address": fields[4],
        "entry_point": fields[5],
        "data_crc": fields[6],
        "os": fields[7],
        "arch": fields[8],
        "type": fields[9],
        "compression": fields[10],
        "name": name,
    }


def parse_trx_header(data: bytes, offset: int = 0) -> dict[str, object] | None:
    """Parse a TRX header at offset, or return None if not present.

    TRX header (28 bytes, little-endian): magic "HDR0", length,
    CRC32, flags, and three partition offsets.
    """
    if offset < 0 or len(data) < offset + 28:
        return None
    if data[offset : offset + 4] != b"HDR0":
        return None
    length, crc, flags, off0, off1, off2 = struct.unpack_from("<6I", data, offset + 4)
    return {
        "format": "trx",
        "offset": offset,
        "length": length,
        "crc32": crc,
        "flags": flags,
        "partition_offsets": [off0, off1, off2],
    }


def _router_filesystems(data: bytes) -> list[dict[str, object]]:
    """List embedded filesystems with offsets, from magic bytes."""
    filesystems: list[dict[str, object]] = []
    for entry in detect_embedded_formats(data):
        if entry["format"] in ("squashfs", "jffs2", "ubifs"):
            filesystems.append(
                {"filesystem": entry["format"], "offset": entry["offset"]}
            )
    return filesystems


# --- Router config-file parsing ------------------------------------------

# Keys whose values are treated as secrets and fully redacted.
_SECRET_KEY_RE = re.compile(
    r"(?i)(?:password|passwd|psk|secret|key|token|ssid)"
)
_DEFAULT_SSID_PREFIXES = (
    "TP-LINK", "TPLink", "NETGEAR", "D-Link", "dlink", "ASUS",
    "Linksys", "FRITZ!Box", "HUAWEI", "Xiaomi", "ZTE", "Tenda",
    "Mercusys", "TOTOLINK",
)
_WEB_ADMIN_RE = re.compile(
    r"(?i)(?:/admin|/login\.asp|/cgi-bin/luci|/webadmin|/manager|/login\.cgi)"
)


def parse_router_config(text: str) -> list[dict[str, object]]:
    """Parse a router config file (OpenWrt UCI, .conf, .cfg, .ini).

    Returns a list of {section, key, value} entries. Values for
    secret-looking keys are fully redacted (``****``); other values
    are truncated to 40 characters. The file itself is never
    modified and no value is written in full when it looks like a
    secret.
    """
    entries: list[dict[str, object]] = []
    section = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        match = re.match(r"config\s+(\S+)(?:\s+['\"]?([^'\"]+)['\"]?)?", line)
        if match:
            section = match.group(1)
            if match.group(2):
                section = f"{section} {match.group(2)}"
            continue
        match = re.match(r"option\s+(\S+)\s+['\"]?([^'\"]*)['\"]?", line)
        if not match:
            match = re.match(r"([^=\s]+)\s*=\s*(.*)$", line)
        if not match:
            continue
        key = match.group(1).strip()
        value = match.group(2).strip().strip("'\"")
        if _SECRET_KEY_RE.search(key):
            display = "****"
        else:
            display = value[:40]
        entries.append({"section": section, "key": key, "value": display})
    return entries


def parse_router_config_file(path: str | Path) -> list[dict[str, object]]:
    """Parse a router config file from disk, with redaction."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"config file not found: {file_path}")
    if file_path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("config file too large (limit 10 MiB)")
    text = file_path.read_text(encoding="utf-8", errors="replace")
    return parse_router_config(text)


# --- Router-specific findings --------------------------------------------

_ROUTER_DEFAULT_RE = re.compile(
    r"(?i)\b(?:admin|root|user)\s*[:=]\s*(?:admin|root|password|123456|1234)\b"
)
_ROUTER_TELNET_RE = re.compile(r"(?i)\btelnet\b")
_ROUTER_SSH_RE = re.compile(r"(?i)\b(?:ssh|dropbear|openssh)\b")


def _ssid_prefix_re() -> re.Pattern[str]:
    prefixes = "|".join(re.escape(p) for p in _DEFAULT_SSID_PREFIXES)
    return re.compile(rf"^(?:{prefixes})[-_ ]?[A-Za-z0-9_-]*$")


def detect_router_findings(strings: list[str]) -> list[dict[str, object]]:
    """Router-specific findings, with redaction.

    Only pattern findings are returned: default-credential patterns,
    default SSID names, web admin paths, and service strings. No
    credential value is ever returned.
    """
    findings: list[dict[str, object]] = []
    checks = (
        (
            "router_default_credential",
            _ROUTER_DEFAULT_RE,
            30,
            "Default credential pattern in router firmware",
            "Replace default credentials with a unique per-device "
            "password set at first setup, and force a password change "
            "on first login.",
        ),
        (
            "router_telnet_service",
            _ROUTER_TELNET_RE,
            10,
            "Telnet service string (cleartext remote access)",
            "Disable Telnet on the router. Use SSH with key "
            "authentication where remote access is required.",
        ),
        (
            "router_ssh_service",
            _ROUTER_SSH_RE,
            5,
            "SSH service string",
            "Confirm SSH is required, disable password "
            "authentication, and use key authentication.",
        ),
        (
            "router_web_admin",
            _WEB_ADMIN_RE,
            5,
            "Web admin path string",
            "Confirm the admin interface is only reachable on the "
            "LAN, uses HTTPS, and has a unique per-device password.",
        ),
    )
    for name, pattern, weight, description, remediation in checks:
        count = 0
        preview = ""
        for text in strings:
            for match in pattern.finditer(text):
                count += 1
                if not preview:
                    preview = redact(match.group(0))
        if count:
            findings.append(
                {
                    "rule": name,
                    "rule_id": name,
                    "description": description,
                    "weight": weight,
                    "severity": severity_for_weight(weight),
                    "remediation": remediation,
                    "count": count,
                    "preview": preview,
                }
            )
    # Default SSID names: a string that is exactly a well-known
    # vendor SSID prefix, optionally with a suffix.
    ssid_re = _ssid_prefix_re()
    count = 0
    preview = ""
    for text in strings:
        if ssid_re.match(text):
            count += 1
            if not preview:
                preview = redact(text)
    if count:
        findings.append(
            {
                "rule": "router_default_ssid",
                "rule_id": "router_default_ssid",
                "description": "Default SSID name pattern",
                "weight": 10,
                "severity": severity_for_weight(10),
                "remediation": "Change the default SSID to a name "
                "that does not identify the router model, and set a "
                "strong unique Wi-Fi password.",
                "count": count,
                "preview": preview,
            }
        )
    return findings


def analyze_router_firmware(
    path: str | Path,
    limit_mb: int | None = None,
    profile: "Profile | str | Path | None" = None,
    rules: list | None = None,
) -> dict[str, object]:
    """Analyze a router firmware file and return a report dictionary.

    The dictionary contains no full secret values. When limit_mb is
    given, string and secret analysis covers only the first
    limit_mb megabytes; SHA-256 and size cover the whole file.
    A profile (id, file, or Profile) is recorded when used;
    otherwise auto-detection is used. Config-style files
    (.conf/.cfg/.ini, or UCI text) are also parsed for keys, with
    secret-looking values redacted.
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
    data = firmware_path.read_bytes()
    window = data if limit_mb is None else data[: limit_mb * 1024 * 1024]
    strings = extract_strings(window)
    findings = detect_secrets(strings)
    seen = {f["rule"] for f in findings}
    for finding in detect_router_findings(strings):
        if finding["rule"] not in seen:
            findings.append(finding)
    if rules:
        from .rules import apply_custom_rules

        seen = {f["rule"] for f in findings}
        for finding in apply_custom_rules(strings, rules):
            if finding["rule"] not in seen:
                findings.append(finding)
    formats = detect_router_formats(window)
    uimage = None
    trx = None
    for entry in formats:
        if entry["format"] == "uimage" and uimage is None:
            uimage = parse_uimage_header(window, int(entry["offset"]))
        if entry["format"] == "trx" and trx is None:
            trx = parse_trx_header(window, int(entry["offset"]))
    config_keys: list[dict[str, object]] = []
    if firmware_path.suffix.lower() in (".conf", ".cfg", ".ini", ".txt") or (
        window[:200].lstrip().startswith(b"config ")
    ):
        try:
            config_keys = parse_router_config(
                window.decode("utf-8", errors="replace")
            )
        except ValueError:
            config_keys = []
    elf_binaries: list[dict[str, object]] = []
    for entry in formats:
        if entry["format"] == "elf":
            parsed = parse_elf(window, int(entry["offset"]))
            if parsed is not None:
                elf_binaries.append(parsed)
    score = min(100, sum(int(f["weight"]) * int(f["count"]) for f in findings))
    return {
        "tool": "boardaudit",
        "kind": "router",
        "file": firmware_path.name,
        "size_bytes": size,
        "sha256": sha256_hex(data),
        "entropy_bits_per_byte": entropy(data),
        "entropy_sections": entropy_by_section(window),
        "embedded_formats": formats,
        "elf_binaries": elf_binaries,
        "archive_entries": list_archive_entries(window),
        "certificates": detect_certificates(window),
        "filesystems": _router_filesystems(window),
        "uimage_header": uimage,
        "trx_header": trx,
        "config_keys": config_keys,
        "duplicate_strings": duplicate_strings(strings),
        "analysis_limit_mb": limit_mb,
        "analysis_window_bytes": len(window),
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


# --- Gateway validation and read-only LAN inventory ----------------------

def validate_gateway(gateway: str) -> str:
    """Validate a gateway address for a router gateway scan.

    Only private LAN IPv4 addresses are allowed. Public addresses,
    localhost, and anything that is not an IPv4 address are rejected.
    """
    if not isinstance(gateway, str) or not gateway.strip():
        raise ValueError("gateway must be a non-empty IPv4 address")
    try:
        address = ipaddress.IPv4Address(gateway.strip())
    except ipaddress.AddressValueError:
        raise ValueError(f"invalid gateway IPv4 address: {gateway!r}")
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
    ):
        raise ValueError(
            f"gateway {gateway!r} is not a private LAN address "
            "(loopback, link-local, reserved, and unspecified "
            "addresses are rejected)"
        )
    if not address.is_private:
        raise ValueError(
            f"gateway {gateway!r} is not a private LAN address "
            "(public addresses are rejected)"
        )
    return str(address)


# Small, well-known OUI prefixes, used only to label a gateway MAC
# when it matches. Anything else is reported as unknown.
_KNOWN_OUI_VENDORS: dict[str, str] = {
    "00:1a:2b": "TP-Link (known OUI prefix)",
    "50:c7:bf": "TP-Link (known OUI prefix)",
    "e4:be:ed": "TP-Link (known OUI prefix)",
    "00:14:22": "Dell (known OUI prefix)",
    "00:1b:21": "Intel (known OUI prefix)",
    "00:23:69": "Cisco (known OUI prefix)",
    "00:24:97": "Cisco (known OUI prefix)",
    "00:1e:49": "Cisco (known OUI prefix)",
    "04:da:d2": "Netgear (known OUI prefix)",
    "c0:ff:d4": "Netgear (known OUI prefix)",
    "00:18:4d": "Netgear (known OUI prefix)",
    "00:0c:43": "Raspberry Pi (known OUI prefix)",
    "b8:27:eb": "Raspberry Pi (known OUI prefix)",
    "dc:a6:32": "Raspberry Pi (known OUI prefix)",
    "f0:9f:c2": "Ubiquiti (known OUI prefix)",
    "80:2a:a8": "Ubiquiti (known OUI prefix)",
    "74:83:c2": "Ubiquiti (known OUI prefix)",
    "00:15:5d": "Microsoft (known OUI prefix)",
    "00:03:ff": "Microsoft (known OUI prefix)",
    "34:29:8f": "Xiaomi (known OUI prefix)",
    "64:cc:2e": "Xiaomi (known OUI prefix)",
    "00:1f:c6": "ASUSTek (known OUI prefix)",
    "04:92:26": "ASUSTek (known OUI prefix)",
    "ac:22:0b": "ASUSTek (known OUI prefix)",
    "00:25:9c": "Huawei (known OUI prefix)",
    "48:46:fb": "Huawei (known OUI prefix)",
    "e8:cd:2d": "Huawei (known OUI prefix)",
}


def vendor_for_mac(mac: str) -> str:
    """Return a vendor label for a MAC address, or 'unknown'.

    Only the OUI prefixes in _KNOWN_OUI_VENDORS are labelled; the
    label says it is a known prefix, not a verified device model.
    """
    prefix = mac.lower()[:8]
    return _KNOWN_OUI_VENDORS.get(prefix, "unknown")


def _default_gateway() -> str:
    """Return the default gateway address, or '' when not found."""
    system = platform.system()
    if system == "Linux":
        output = _run(["ip", "route", "show", "default"])
        match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", output)
        if match:
            return match.group(1)
        output = _run(["route", "-n"])
        for line in output.splitlines():
            parts = line.split()
            # "0.0.0.0" here is the default-route destination read
            # from `ip route` output, not a socket bind address.
            if parts and parts[0] == "0.0.0.0" and len(parts) > 1:  # nosec B104
                return parts[1]
    elif system == "Darwin":
        output = _run(["route", "-n", "get", "default"])
        match = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", output)
        if match:
            return match.group(1)
    elif system == "Windows":
        output = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                "Select-Object -First 1 -ExpandProperty NextHop",
            ]
        )
        candidate = output.strip().splitlines()
        if candidate and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", candidate[0].strip()):
            return candidate[0].strip()
    return ""


def _gateway_mac(gateway: str) -> str:
    """Return the MAC address for a gateway, or '' when not found.

    Uses the read-only neighbour/ARP table; no packets are sent to
    discover it beyond the table lookup.
    """
    system = platform.system()
    if system == "Linux":
        output = _run(["ip", "neigh", "show", gateway])
        match = re.search(r"lladdr ((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", output)
        if match:
            return match.group(1).lower()
        output = _run(["arp", "-n", gateway])
    elif system == "Darwin":
        output = _run(["arp", "-n", gateway])
    elif system == "Windows":
        output = _run(["powershell", "-NoProfile", "-Command", f"arp -a {gateway}"])
    else:
        return ""
    match = re.search(r"((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})", output or "")
    if match:
        return match.group(1).lower().replace("-", ":")
    return ""


def router_inventory() -> dict[str, object]:
    """Read-only LAN inventory: gateway and local interfaces.

    No other hosts are scanned. The gateway MAC is read from the
    neighbour/ARP table when present.
    """
    gateway = _default_gateway()
    mac = _gateway_mac(gateway) if gateway else ""
    return {
        "system": platform.system(),
        "default_gateway": gateway,
        "gateway_mac": mac,
        "gateway_vendor": vendor_for_mac(mac) if mac else "unknown",
        "interfaces": list_network_adapters(),
    }


def _ping_once(host: str, timeout_s: int = 2) -> bool:
    """One ICMP ping. Returns True when a reply is received."""
    system = platform.system()
    if system == "Windows":
        argv = ["ping", "-n", "1", "-w", str(timeout_s * 1000), host]
    elif system == "Darwin":
        argv = ["ping", "-c", "1", "-t", str(timeout_s), host]
    else:
        argv = ["ping", "-c", "1", "-W", str(timeout_s), host]
    if shutil.which(argv[0]) is None:
        return False
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout_s + 5, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _tcp_connect(host: str, port: int, timeout_s: int = 2) -> str:
    """One TCP connect. Returns 'open', 'closed', or 'timeout'."""
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return "open"
    except socket.timeout:
        return "timeout"
    except OSError:
        return "closed"


def router_gateway_scan(gateway: str, authorized: bool) -> dict[str, object]:
    """Read-only gateway check: one ping, TCP connect to 80 and 443.

    The gateway must be a private LAN IPv4 address, and --authorized
    is required. No login, no config download, no other ports.
    """
    if not authorized:
        raise ValueError(
            "router gateway scan refused: --authorized is required. "
            "Only scan a gateway you own or are authorized to audit."
        )
    validated = validate_gateway(gateway)
    ports = {
        80: _tcp_connect(validated, 80),
        443: _tcp_connect(validated, 443),
    }
    return {
        "tool": "boardaudit",
        "kind": "router-gateway-scan",
        "gateway": validated,
        "gateway_mac": _gateway_mac(validated),
        "authorized": True,
        "ping_ok": _ping_once(validated),
        "ports": {str(port): state for port, state in ports.items()},
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "note": (
            "Read-only check: one ICMP ping and one TCP connect to "
            "ports 80 and 443 only. No login, no config download."
        ),
    }


if __name__ == "__main__":  # pragma: no cover - manual smoke check
    print(router_inventory(), file=sys.stderr)
