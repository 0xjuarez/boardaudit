"""Unified device profiles for boardaudit.

One profile schema covers boards, routers, and disks, so the same
commands list, show, validate, and extend every device type.
Profiles are data only: a profile never contains code, shell
commands, or credentials. Built-in profiles cover the most common
devices; users add their own with ``boardaudit profiles new`` and
``boardaudit profiles add``.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
PROFILE_KINDS = ("board", "router", "disk")
MAX_STRING_LEN = 2000
MAX_NAME_LEN = 120

# Strings that look like shell commands, embedded commands, URLs
# with credentials, or secret material. Any profile value matching
# one of these is rejected at validation time.
_SHELL_FRAGMENTS = ("$(", "`", "${", "&&", "||", "\n", "\r")
_URL_WITH_CREDENTIALS_RE = re.compile(r"://[^/\s]*:[^/\s@]+@")
_SECRET_VALUE_RE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password|passwd)\s*=\s*['\"]?[^\s'\";]{8,}"
)


class ProfileError(Exception):
    """Raised when a profile is invalid or cannot be loaded."""


@dataclass
class Profile:
    profile_id: str
    kind: str
    name: str
    family: str = ""
    soc: str = ""
    vendor_family: str = ""
    flash_size: int = 0
    app_offset: int = 0
    default_baud: int = 0
    acquisition_tool: str = ""
    filesystem: str = ""
    interface: str = ""
    capacity_bytes: int = 0
    notes: str = ""
    extra: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.profile_id,
            "kind": self.kind,
            "name": self.name,
            "family": self.family,
            "soc": self.soc,
            "vendor_family": self.vendor_family,
            "flash_size": self.flash_size,
            "app_offset": self.app_offset,
            "default_baud": self.default_baud,
            "acquisition_tool": self.acquisition_tool,
            "filesystem": self.filesystem,
            "interface": self.interface,
            "capacity_bytes": self.capacity_bytes,
            "notes": self.notes,
            "extra": dict(self.extra),
        }


def _board(
    profile_id: str,
    name: str,
    family: str,
    flash_size: int,
    app_offset: int,
    tool: str,
    notes: str = "",
    **extra: object,
) -> dict[str, object]:
    return {
        "id": profile_id,
        "kind": "board",
        "name": name,
        "family": family,
        "flash_size": flash_size,
        "app_offset": app_offset,
        "default_baud": 115200,
        "acquisition_tool": tool,
        "notes": notes,
        "extra": dict(extra),
    }


def _router(
    profile_id: str,
    soc: str,
    vendor_family: str,
    flash_size: int = 16 * 1024 * 1024,
    filesystem: str = "SquashFS / JFFS2",
    notes: str = "",
    **extra: object,
) -> dict[str, object]:
    return {
        "id": profile_id,
        "kind": "router",
        "name": soc,
        "soc": soc,
        "vendor_family": vendor_family,
        "flash_size": flash_size,
        "filesystem": filesystem,
        "notes": notes
        or "Read the flash through the vendor recovery or serial "
        "interface on a device you own.",
        "extra": dict(extra),
    }


def _disk(
    profile_id: str,
    name: str,
    interface: str,
    filesystem: str = "",
    notes: str = "",
    **extra: object,
) -> dict[str, object]:
    return {
        "id": profile_id,
        "kind": "disk",
        "name": name,
        "interface": interface,
        "filesystem": filesystem,
        "notes": notes,
        "extra": dict(extra),
    }


# --- Built-in catalog: the most common devices ---------------------------

_BUILTIN_DATA: list[dict[str, object]] = [
    # Boards (ESP32 family, ESP8266, STM32, RP2040, nRF52, AVR,
    # plus the next most common: ESP32-H2, STM32H7, SAMD21, Teensy 4.x).
    _board("esp32", "ESP32", "ESP32", 4 * 1024 * 1024, 0x10000, "esptool",
           "ESP32-WROOM / WROVER class boards."),
    _board("esp32-s2", "ESP32-S2", "ESP32", 4 * 1024 * 1024, 0x10000, "esptool"),
    _board("esp32-s3", "ESP32-S3", "ESP32", 8 * 1024 * 1024, 0x10000, "esptool"),
    _board("esp32-c3", "ESP32-C3", "ESP32", 4 * 1024 * 1024, 0x10000, "esptool"),
    _board("esp32-c6", "ESP32-C6", "ESP32", 4 * 1024 * 1024, 0x10000, "esptool"),
    _board("esp32-h2", "ESP32-H2", "ESP32", 4 * 1024 * 1024, 0x10000, "esptool",
           "ESP32-H2 with IEEE 802.15.4 / Thread support."),
    _board("esp8266", "ESP8266", "ESP8266", 4 * 1024 * 1024, 0x10000, "esptool"),
    _board("stm32f4", "STM32F4", "STM32", 1 * 1024 * 1024, 0x08000000, "st-flash",
           "Acquisition via st-flash or OpenOCD; both are optional and must already be installed."),
    _board("stm32l4", "STM32L4", "STM32", 1 * 1024 * 1024, 0x08000000, "st-flash",
           "Acquisition via st-flash or OpenOCD; both are optional and must already be installed."),
    _board("stm32h7", "STM32H7", "STM32", 2 * 1024 * 1024, 0x08000000, "st-flash",
           "Acquisition via st-flash or OpenOCD; both are optional and must already be installed."),
    _board("rp2040", "RP2040", "RP2040", 2 * 1024 * 1024, 0x10000000, "picotool",
           "Acquisition via picotool; optional and must already be installed. RP2040 flash is normally read through the USB mass-storage / picotool interface, not a serial dump."),
    _board("nrf52840", "nRF52840", "nRF52", 1 * 1024 * 1024, 0x00000000, "nrfutil",
           "Acquisition via nrfutil / J-Link; optional and must already be installed."),
    _board("atmega328p", "ATmega328P", "AVR", 32 * 1024, 0x0000, "avrdude",
           "Acquisition via avrdude; optional and must already be installed."),
    _board("samd21", "SAMD21", "ARM Cortex-M0+", 256 * 1024, 0x0000, "openocd",
           "Acquisition via OpenOCD or a CMSIS-DAP probe; optional and must already be installed."),
    _board("teensy41", "Teensy 4.1", "ARM Cortex-M7", 8 * 1024 * 1024, 0x60000000, "teensy_loader_cli",
           "Acquisition via Teensy Loader / teensy_loader_cli; optional and must already be installed."),
    # Routers by SoC, plus a generic OpenWrt-compatible profile.
    _router("mediatek-mt7620", "MediaTek MT7620", "MediaTek"),
    _router("mediatek-mt7621", "MediaTek MT7621", "MediaTek"),
    _router("mediatek-mt7981", "MediaTek MT7981", "MediaTek",
            flash_size=32 * 1024 * 1024, filesystem="SquashFS / UBIFS"),
    _router("mediatek-mt7986", "MediaTek MT7986", "MediaTek",
            flash_size=32 * 1024 * 1024, filesystem="SquashFS / UBIFS"),
    _router("qca9531", "Qualcomm Atheros QCA9531", "Qualcomm Atheros"),
    _router("qca9563", "Qualcomm Atheros QCA9563", "Qualcomm Atheros"),
    _router("qca-ipq4019", "Qualcomm IPQ4019", "Qualcomm",
            flash_size=32 * 1024 * 1024),
    _router("qca-ipq8074", "Qualcomm IPQ8074", "Qualcomm",
            flash_size=32 * 1024 * 1024, filesystem="SquashFS / UBIFS"),
    _router("bcm63xx", "Broadcom BCM63xx", "Broadcom"),
    _router("bcm47xx", "Broadcom BCM47xx", "Broadcom"),
    _router("rtl8197", "Realtek RTL8197", "Realtek"),
    _router("rtl8676", "Realtek RTL8676", "Realtek"),
    _router("generic-openwrt", "Generic OpenWrt-compatible", "Generic",
            filesystem="SquashFS / JFFS2",
            notes="Generic profile for routers running OpenWrt or a "
            "compatible firmware layout. Use it when the exact SoC is "
            "unknown; auto-detection still applies."),
    # Storage: the most common disk and card types.
    _disk("sata-hdd", "SATA hard disk drive", "SATA",
          filesystem="NTFS / exFAT / ext4",
          notes="Rotating hard disk drive on SATA. Image the disk to a file first; analyze the image."),
    _disk("sata-ssd", "SATA solid-state drive", "SATA",
          filesystem="NTFS / exFAT / ext4",
          notes="SATA solid-state drive. Image the disk to a file first; analyze the image."),
    _disk("nvme-ssd", "NVMe solid-state drive", "NVMe",
          filesystem="NTFS / exFAT / ext4",
          notes="NVMe solid-state drive (M.2 or U.2). Image the disk to a file first; analyze the image."),
    _disk("usb-flash", "USB flash drive", "USB",
          filesystem="FAT32 / exFAT",
          notes="USB 2.0 / 3.0 flash drive. Image the drive to a file first; analyze the image."),
    _disk("sd-card", "SD card", "SD",
          filesystem="FAT32 / exFAT",
          notes="Full-size SD card, commonly FAT32 or exFAT."),
    _disk("microsd", "microSD card", "SD",
          filesystem="FAT32 / exFAT",
          notes="microSD card, commonly FAT32 or exFAT."),
    _disk("emmc", "eMMC storage", "eMMC",
          filesystem="ext4 / FAT32",
          notes="Embedded eMMC storage, common in single-board computers and embedded devices."),
]

def _build_builtins() -> dict[str, Profile]:
    profiles: dict[str, Profile] = {}
    for data in _BUILTIN_DATA:
        profile, errors = validate_profile_data(data)
        if errors:  # pragma: no cover - built-ins are validated by tests
            raise ProfileError(f"built-in profile invalid: {errors}")
        profiles[profile.profile_id] = profile
    return profiles


# --- Validation ------------------------------------------------------------


def _check_string(value: object, field_name: str, errors: list[str]) -> str:
    if not isinstance(value, str):
        errors.append(f"profile field {field_name!r} must be a string")
        return ""
    if len(value) > MAX_STRING_LEN:
        errors.append(f"profile field {field_name!r} is too long")
    for fragment in _SHELL_FRAGMENTS:
        if fragment in value:
            errors.append(
                f"profile field {field_name!r} contains a shell fragment "
                f"({fragment!r}); profiles are data only"
            )
            break
    if _URL_WITH_CREDENTIALS_RE.search(value):
        errors.append(
            f"profile field {field_name!r} contains a URL with credentials"
        )
    if _SECRET_VALUE_RE.search(value) or _ASSIGNMENT_RE.search(value):
        errors.append(
            f"profile field {field_name!r} looks like it contains secret "
            "material; profiles must not contain secrets"
        )
    return value


def _check_int(value: object, field_name: str, errors: list[str]) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        errors.append(f"profile field {field_name!r} must be an integer")
        return 0
    if value < 0 or value > 1024 * 1024 * 1024 * 1024:
        errors.append(f"profile field {field_name!r} is out of range")
        return 0
    return value


def validate_profile_data(data: object) -> tuple[Profile | None, list[str]]:
    """Validate raw profile data, returning (profile, errors).

    Errors is empty on success. Validation is strict: unknown
    top-level fields are rejected, so a typo cannot silently
    change a profile.
    """
    errors: list[str] = []
    if not isinstance(data, dict):
        return None, ["profile must be a mapping (object)"]
    allowed = {
        "id", "kind", "name", "family", "soc", "vendor_family",
        "flash_size", "app_offset", "default_baud", "acquisition_tool",
        "filesystem", "interface", "capacity_bytes", "notes", "extra",
    }
    for key in data:
        if key not in allowed:
            errors.append(f"unknown profile field: {key!r}")
    profile_id = data.get("id", "")
    if not isinstance(profile_id, str) or not PROFILE_ID_RE.match(profile_id):
        errors.append("profile id must match [A-Za-z0-9_-]+")
        profile_id = ""
    kind = data.get("kind", "")
    if kind not in PROFILE_KINDS:
        errors.append(f"profile kind must be one of {', '.join(PROFILE_KINDS)}")
        kind = ""
    name = data.get("name", "")
    if not isinstance(name, str) or not name.strip() or len(name) > MAX_NAME_LEN:
        errors.append("profile name must be a non-empty string (max 120 chars)")
        name = ""
    fields: dict[str, object] = {}
    for field_name in (
        "family", "soc", "vendor_family", "acquisition_tool",
        "filesystem", "interface", "notes",
    ):
        fields[field_name] = _check_string(data.get(field_name, ""), field_name, errors)
    # A semicolon in the acquisition tool would let a profile smuggle
    # a second shell command; reject it even though ";" is allowed
    # in free-text notes.
    if ";" in str(fields["acquisition_tool"]):
        errors.append(
            "profile field 'acquisition_tool' must be a single tool name, "
            "not a shell command"
        )
    for field_name in ("flash_size", "app_offset", "default_baud", "capacity_bytes"):
        fields[field_name] = _check_int(data.get(field_name, 0), field_name, errors)
    extra = data.get("extra", {})
    if extra is None:
        extra = {}
    if not isinstance(extra, dict):
        errors.append("profile field 'extra' must be a table")
        extra = {}
    else:
        for key, value in extra.items():
            if not isinstance(key, str) or not PROFILE_ID_RE.match(key):
                errors.append(f"profile extra key must match [A-Za-z0-9_-]+: {key!r}")
            elif not isinstance(value, (str, int, bool, list)):
                errors.append(f"profile extra value for {key!r} must be a string, integer, boolean, or list")
            elif isinstance(value, list) and not all(
                isinstance(item, (str, int, bool)) for item in value
            ):
                errors.append(f"profile extra list for {key!r} must contain only strings, integers, or booleans")
            elif isinstance(value, str):
                _check_string(value, f"extra.{key}", errors)
    if errors:
        return None, errors
    return Profile(
        profile_id=str(profile_id),
        kind=str(kind),
        name=str(name).strip(),
        family=str(fields["family"]),
        soc=str(fields["soc"]),
        vendor_family=str(fields["vendor_family"]),
        flash_size=int(fields["flash_size"]),
        app_offset=int(fields["app_offset"]),
        default_baud=int(fields["default_baud"]),
        acquisition_tool=str(fields["acquisition_tool"]),
        filesystem=str(fields["filesystem"]),
        interface=str(fields["interface"]),
        capacity_bytes=int(fields["capacity_bytes"]),
        notes=str(fields["notes"]),
        extra=dict(extra),
    ), []


def load_profile_data(raw: object) -> Profile:
    """Validate raw data and return a Profile, or raise ProfileError."""
    profile, errors = validate_profile_data(raw)
    if profile is None:
        raise ProfileError("invalid profile: " + "; ".join(errors))
    return profile


BUILTIN_PROFILES: dict[str, Profile] = _build_builtins()


# --- Loading from files and directories ------------------------------------


def user_profiles_dir() -> Path:
    """User profiles directory: ~/.config/boardaudit/profiles/."""
    return Path.home() / ".config" / "boardaudit" / "profiles"


def _parse_profile_file(path: Path) -> object:
    """Parse a profile file (JSON, TOML, or YAML when PyYAML is present)."""
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            return json.loads(path.read_text(encoding="utf-8"))
        if suffix == ".toml":
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
            if isinstance(raw, dict) and isinstance(raw.get("profile"), dict):
                return raw["profile"]
            return raw
        if suffix in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore[import-not-found]
            except ImportError:
                raise ProfileError(
                    "YAML profiles need PyYAML installed; use JSON or TOML instead"
                ) from None
            return yaml.safe_load(path.read_text(encoding="utf-8"))
    except ProfileError:
        raise
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        raise ProfileError(f"cannot read profile file {path}: {exc}") from exc
    raise ProfileError(
        f"unsupported profile file type: {path.suffix!r} "
        "(use .json, .toml, or .yaml)"
    )


def load_profile_file(path: str | Path) -> Profile:
    """Load and validate one profile file."""
    file_path = Path(path)
    if not file_path.is_file():
        raise ProfileError(f"profile file not found: {file_path}")
    return load_profile_data(_parse_profile_file(file_path))


def load_user_profiles(
    extra_dirs: list[str | Path] | None = None,
) -> tuple[dict[str, Profile], list[str]]:
    """Load user profiles from the user directory and ./profiles/.

    User profiles override built-ins with the same id. Returns
    (merged_profiles, warnings). A broken user profile is reported
    as a warning and skipped, never silently applied.
    """
    warnings: list[str] = []
    merged: dict[str, Profile] = dict(BUILTIN_PROFILES)
    dirs: list[Path] = [user_profiles_dir(), Path.cwd() / "profiles"]
    if extra_dirs:
        dirs.extend(Path(d) for d in extra_dirs)
    for directory in dirs:
        if not directory.is_dir():
            continue
        for file_path in sorted(directory.iterdir()):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in (".json", ".toml", ".yaml", ".yml"):
                continue
            try:
                profile = load_profile_file(file_path)
            except ProfileError as exc:
                warnings.append(f"skipping profile {file_path}: {exc}")
                continue
            if profile.profile_id in merged and profile.profile_id in BUILTIN_PROFILES:
                warnings.append(
                    f"user profile {profile.profile_id!r} overrides the built-in profile"
                )
            merged[profile.profile_id] = profile
    return merged, warnings


def list_profiles(
    kind: str | None = None,
    extra_dirs: list[str | Path] | None = None,
) -> list[Profile]:
    """All profiles (built-in plus user), optionally filtered by kind."""
    merged, _warnings = load_user_profiles(extra_dirs)
    profiles = [merged[key] for key in sorted(merged)]
    if kind is not None:
        if kind not in PROFILE_KINDS:
            raise ProfileError(f"unknown profile kind: {kind!r}")
        profiles = [p for p in profiles if p.kind == kind]
    return profiles


def get_profile(
    profile_id: str,
    extra_dirs: list[str | Path] | None = None,
) -> Profile:
    """Return a profile by id (built-in or user), or raise ProfileError."""
    if not isinstance(profile_id, str) or not PROFILE_ID_RE.match(profile_id.strip()):
        raise ProfileError(f"invalid profile id: {profile_id!r}")
    merged, _warnings = load_user_profiles(extra_dirs)
    profile = merged.get(profile_id.strip())
    if profile is None:
        known = ", ".join(sorted(merged))
        raise ProfileError(f"unknown profile: {profile_id!r}. Known: {known}")
    return profile


def resolve_profile_arg(
    arg: str | Path | None,
    extra_dirs: list[str | Path] | None = None,
) -> Profile | None:
    """Resolve --profile: a file path loads that file, an id looks it up.

    Returns None when arg is None.
    """
    if arg is None:
        return None
    candidate = Path(str(arg))
    if candidate.is_file():
        return load_profile_file(candidate)
    return get_profile(str(arg), extra_dirs)


# --- Creating and adding user profiles -------------------------------------


def profile_template(kind: str, profile_id: str) -> dict[str, object]:
    """Starter profile data for a new profile of the given kind."""
    if kind not in PROFILE_KINDS:
        raise ProfileError(f"unknown profile kind: {kind!r}")
    if not PROFILE_ID_RE.match(profile_id):
        raise ProfileError(f"invalid profile id: {profile_id!r}")
    base: dict[str, object] = {
        "id": profile_id,
        "kind": kind,
        "name": profile_id,
        "notes": "Describe this device here.",
        "extra": {},
    }
    if kind == "board":
        base.update(
            {
                "family": "",
                "flash_size": 0,
                "app_offset": 0,
                "default_baud": 115200,
                "acquisition_tool": "",
            }
        )
    elif kind == "router":
        base.update(
            {
                "soc": "",
                "vendor_family": "",
                "flash_size": 0,
                "filesystem": "SquashFS / JFFS2",
            }
        )
    else:
        base.update({"interface": "", "filesystem": ""})
    return base


def write_profile_template(
    kind: str, profile_id: str, path: str | Path
) -> Path:
    """Write a starter profile file (JSON) the user can edit."""
    target = Path(path)
    data = profile_template(kind, profile_id)
    load_profile_data(data)  # validate the template before writing it
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def add_profile_file(
    src: str | Path, force: bool = False
) -> Path:
    """Validate a profile file and copy it into the user profiles dir.

    Refuses to overwrite an existing profile with the same id
    unless --force is passed.
    """
    profile = load_profile_file(src)
    directory = user_profiles_dir()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{profile.profile_id}.json"
    if target.exists() and not force:
        raise ProfileError(
            f"profile {profile.profile_id!r} already exists at {target}. "
            "Pass --force to overwrite it."
        )
    target.write_text(
        json.dumps(profile.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target


def export_profiles(
    path: str | Path,
    kind: str | None = None,
    extra_dirs: list[str | Path] | None = None,
) -> Path:
    """Export the merged profile catalog (built-in plus user) as JSON."""
    target = Path(path)
    data = [p.to_dict() for p in list_profiles(kind, extra_dirs)]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target
