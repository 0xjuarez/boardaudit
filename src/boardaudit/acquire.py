"""Authorized-only hardware acquisition.

A hardware dump requires --authorized. boardaudit never installs,
downloads, clones, or runs anything as root to acquire firmware.
Acquisition tools must already be installed; a missing tool is a
clear error, not an automatic install.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .analysis import analyze_firmware
from .boards import get_board
from .inventory import list_serial_ports
from .report import scan_dir, write_json_report, write_markdown_report

BAUD_FALLBACK = (115200, 230400, 460800, 921600)
_PORT_RE = re.compile(r"^[A-Za-z0-9_./-]+$")


class AcquisitionError(Exception):
    """Raised when acquisition cannot proceed safely."""


def _validate_port(port: str, allow_port: str | None) -> str:
    if not isinstance(port, str) or not _PORT_RE.match(port):
        raise AcquisitionError(f"invalid port value: {port!r}")
    if ".." in port:
        raise AcquisitionError(f"invalid port value: {port!r}")
    discovered = {entry["device"] for entry in list_serial_ports()}
    allowed = set()
    if allow_port:
        if not _PORT_RE.match(allow_port) or ".." in allow_port:
            raise AcquisitionError(f"invalid --allow-port value: {allow_port!r}")
        allowed.add(allow_port)
    if port not in discovered and port not in allowed:
        raise AcquisitionError(
            f"port {port!r} was not found in the discovered serial ports "
            f"({sorted(discovered) or 'none found'}). "
            "Use --allow-port to allow it explicitly, or connect the device first."
        )
    return port


def _find_esptool() -> str:
    for name in ("esptool", "esptool.py"):
        path = shutil.which(name)
        if path:
            return path
    raise AcquisitionError(
        "esptool was not found. Install esptool separately "
        "(pip install 'boardaudit[hardware]' or your system package manager) "
        "and try again. boardaudit does not install tools at runtime."
    )


def scan(
    port: str,
    board_id: str,
    authorized: bool,
    scans_dir: str | Path = "boardaudit-out",
    allow_port: str | None = None,
    baud: int | None = None,
) -> dict[str, object]:
    """Dump flash from an authorized device and analyze it.

    Returns the report dictionary. The firmware file and reports are
    written under scans_dir/<scan-id>/.
    """
    if not authorized:
        raise AcquisitionError(
            "hardware dump refused: --authorized is required. "
            "Only dump firmware from devices you own or are authorized to audit."
        )
    profile = get_board(board_id)
    validated_port = _validate_port(port, allow_port)

    # Only ESP-family boards are acquired through esptool in this release.
    # Other profiles document their acquisition tool; attempting a serial
    # esptool dump against them would be wrong, so refuse clearly.
    if profile.family not in ("ESP32", "ESP8266"):
        raise AcquisitionError(
            f"board {profile.board_id!r} uses {profile.acquisition_tool} for "
            "acquisition, which boardaudit 0.1.0 does not drive automatically. "
            "Use the board's own tool to obtain a firmware image, then run "
            "`boardaudit analyze <firmware.bin>` on the file."
        )
    esptool = _find_esptool()

    scan_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    directory = scan_dir(scans_dir, scan_id)
    (directory / "dump").mkdir(parents=True, exist_ok=True)
    firmware_path = directory / "dump" / "firmware.bin"

    bauds = (baud,) if baud else BAUD_FALLBACK
    size_arg = str(profile.flash_size)
    last_error = ""
    for attempt_baud in bauds:
        argv = [
            esptool,
            "--port",
            validated_port,
            "--baud",
            str(attempt_baud),
            "read_flash",
            "0x0",
            size_arg,
            str(firmware_path),
        ]
        try:
            result = subprocess.run(
                argv, capture_output=True, text=True, timeout=300, check=False
            )
        except subprocess.TimeoutExpired:
            last_error = f"timeout at baud {attempt_baud}"
            continue
        if result.returncode == 0 and firmware_path.is_file():
            break
        last_error = (result.stderr or result.stdout or "").strip()[-500:]
    else:
        raise AcquisitionError(f"flash dump failed at all baud rates: {last_error}")

    report = analyze_firmware(firmware_path)
    report["board"] = profile.board_id
    report["port"] = validated_port
    report["authorized"] = True
    report["scan_id"] = scan_id
    write_json_report(directory, report)
    write_markdown_report(directory, report)
    return report
