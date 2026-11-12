"""Configuration file support: boardaudit.toml / .boardaudit.toml.

The config file is searched in the current working directory, or at
an explicit path. Only TOML files are read, using the standard
library tomllib parser; no code is executed from a config file.

Redaction is always on. A config file that tries to turn redaction
off is ignored for that key, and a warning is returned so the user
sees that the attempt had no effect.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

CONFIG_FILENAMES = ("boardaudit.toml", ".boardaudit.toml")

DEFAULT_CONFIG: dict[str, object] = {
    "output_dir": "boardaudit-out",
    "redaction": True,
    "risk_thresholds": {"medium": 25, "high": 50, "critical": 80},
}


def find_config_file(start: Path | None = None) -> Path | None:
    """Return the first config file found in start (default: cwd)."""
    directory = Path(start) if start is not None else Path.cwd()
    for name in CONFIG_FILENAMES:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def load_config(path: str | Path | None = None) -> tuple[dict[str, object], list[str]]:
    """Load a config file and return (config, warnings).

    Missing files, unreadable files, and invalid TOML all fall back
    to the defaults with a warning; they never stop a run.
    """
    config: dict[str, object] = {
        "output_dir": DEFAULT_CONFIG["output_dir"],
        "redaction": True,
        "risk_thresholds": dict(DEFAULT_CONFIG["risk_thresholds"]),  # type: ignore[arg-type]
    }
    warnings: list[str] = []
    config_path: Path | None = None
    if path is not None:
        config_path = Path(path)
        if not config_path.is_file():
            warnings.append(f"config file not found: {config_path}")
            return config, warnings
    else:
        config_path = find_config_file()
    if config_path is None:
        return config, warnings
    try:
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        warnings.append(f"config file {config_path} could not be read: {exc}")
        return config, warnings
    table = raw.get("boardaudit", raw if isinstance(raw, dict) else {})
    if not isinstance(table, dict):
        warnings.append("config [boardaudit] table is not a table; using defaults")
        return config, warnings
    output_dir = table.get("output_dir")
    if isinstance(output_dir, str) and output_dir.strip():
        config["output_dir"] = output_dir.strip()
    else:
        if "output_dir" in table:
            warnings.append("config output_dir must be a non-empty string; using default")
    # Redaction is always on. A config that tries to disable it is
    # ignored, with a warning.
    redaction = table.get("redaction")
    if redaction is False:
        warnings.append(
            "config tried to disable redaction; redaction stays on and "
            "the setting was ignored"
        )
    elif redaction is not True and redaction is not None:
        warnings.append("config redaction must be a boolean; using true")
    thresholds = table.get("risk_thresholds")
    if isinstance(thresholds, dict):
        merged = dict(config["risk_thresholds"])  # type: ignore[arg-type]
        for key in ("medium", "high", "critical"):
            value = thresholds.get(key)
            if isinstance(value, int) and 0 <= value <= 100:
                merged[key] = value
            elif key in thresholds:
                warnings.append(
                    f"config risk_thresholds.{key} must be an integer 0-100; "
                    "using default"
                )
        if (
            merged["medium"] < merged["high"] < merged["critical"]  # type: ignore[operator]
        ):
            config["risk_thresholds"] = merged
        else:
            warnings.append(
                "config risk_thresholds must satisfy medium < high < critical; "
                "using defaults"
            )
    elif thresholds is not None:
        warnings.append("config risk_thresholds must be a table; using defaults")
    return config, warnings
