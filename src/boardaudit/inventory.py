"""Read-only hardware inventory.

No root required where possible. No packet capture, no promiscuous
mode, no Wi-Fi cracking. All external commands run with argument
lists only (no shell), with a timeout, and their output is parsed as
text. Missing tools are reported, never installed.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from pathlib import Path


def _run(argv: list[str], timeout: int = 10) -> str:
    """Run a command with an argument list and return stdout as text.

    Returns an empty string when the tool is missing or fails. Never
    uses a shell.
    """
    if not argv or shutil.which(argv[0]) is None:
        return ""
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout or ""


def list_serial_ports() -> list[dict[str, str]]:
    """List serial ports. Uses pyserial when available, else a directory scan."""
    try:
        from serial.tools import list_ports  # type: ignore

        ports: list[dict[str, str]] = []
        for port in list_ports.comports():
            ports.append(
                {
                    "device": str(port.device),
                    "description": str(port.description or ""),
                }
            )
        return ports
    except Exception:
        pass
    # Fallback without pyserial: common device nodes on Unix.
    patterns = ["/dev/ttyUSB*", "/dev/ttyACM*", "/dev/cu.*"]
    found: list[dict[str, str]] = []
    for pattern in patterns:
        for path in sorted(Path("/dev").glob(pattern.replace("/dev/", ""))):
            found.append({"device": str(path), "description": ""})
    return found


def list_usb_devices() -> list[str]:
    """List USB devices as short text lines (read-only inventory)."""
    system = platform.system()
    if system == "Linux":
        output = _run(["lsusb"])
    elif system == "Darwin":
        output = _run(["system_profiler", "SPUSBDataType"])
    elif system == "Windows":
        output = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-PnpDevice -Class USB | Select-Object -ExpandProperty FriendlyName",
            ]
        )
    else:
        return []
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return lines[:200]


def list_network_adapters() -> list[dict[str, str]]:
    """List network adapters: name, MAC address, driver/state where available."""
    system = platform.system()
    adapters: list[dict[str, str]] = []
    if system == "Linux":
        output = _run(["ip", "-brief", "link"])
        if not output:
            output = _run(["ifconfig", "-a"])
        for line in output.splitlines():
            parts = line.split()
            if not parts:
                continue
            name = parts[0].rstrip(":")
            mac = ""
            state = ""
            for token in parts:
                if re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", token):
                    mac = token.lower()
                if token.upper() in ("UP", "DOWN", "UNKNOWN"):
                    state = token.upper()
            adapters.append({"name": name, "mac": mac, "state": state})
        return adapters
    if system == "Darwin":
        output = _run(["ifconfig"])
        current: dict[str, str] = {}
        for line in output.splitlines():
            if line and not line.startswith((" ", "\t")):
                if current:
                    adapters.append(current)
                current = {"name": line.split(":")[0], "mac": "", "state": ""}
            match = re.search(r"ether ((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", line)
            if match and current:
                current["mac"] = match.group(1).lower()
            if "status: active" in line and current:
                current["state"] = "UP"
        if current:
            adapters.append(current)
        return adapters
    if system == "Windows":
        output = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-NetAdapter | Format-Table -HideTableHeaders Name, MacAddress, Status",
            ]
        )
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                adapters.append(
                    {
                        "name": parts[0],
                        "mac": parts[1].lower() if "-" in parts[1] else "",
                        "state": parts[-1] if parts else "",
                    }
                )
        return adapters
    return adapters


def inventory() -> dict[str, object]:
    """Return the full read-only inventory."""
    return {
        "system": platform.system(),
        "serial_ports": list_serial_ports(),
        "usb_devices": list_usb_devices(),
        "network_adapters": list_network_adapters(),
    }
