"""Report storage and rendering.

All firmware-derived text is escaped when rendered as Markdown/HTML.
JSON output uses json.dump, which escapes control characters. Scan ids
are validated so a scan id cannot escape the scans directory.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

SCAN_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")

DEFAULT_SCANS_DIR = Path("boardaudit-out")

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SARIF_LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def max_severity(report: dict) -> str:
    """Highest finding severity in a report ('none' when no findings)."""
    best = "none"
    best_rank = -1
    for finding in report.get("findings", []):
        rank = SEVERITY_ORDER.get(str(finding.get("severity", "low")), 0)
        if rank > best_rank:
            best_rank = rank
            best = str(finding.get("severity", "low"))
    return best


def severity_threshold_met(report: dict, threshold: str | None) -> bool:
    """True when the report has a finding at or above the threshold."""
    if threshold is None:
        return False
    if threshold not in SEVERITY_ORDER:
        raise ValueError(
            f"invalid severity threshold: {threshold!r}. "
            f"Use one of {', '.join(SEVERITY_ORDER)}"
        )
    return SEVERITY_ORDER.get(max_severity(report), -1) >= SEVERITY_ORDER[threshold]


def validate_scan_id(scan_id: str) -> str:
    """Return scan_id if valid, otherwise raise ValueError."""
    if not isinstance(scan_id, str) or not SCAN_ID_RE.match(scan_id):
        raise ValueError(
            f"invalid scan id: {scan_id!r}. "
            "Scan ids must match [A-Za-z0-9_-]+"
        )
    return scan_id


def scan_dir(base: str | Path, scan_id: str) -> Path:
    """Return the directory for a scan, guaranteed to stay under base."""
    validate_scan_id(scan_id)
    base_path = Path(base).resolve()
    target = (base_path / scan_id).resolve()
    if target != base_path and base_path not in target.parents:
        raise ValueError(f"scan id escapes scans directory: {scan_id!r}")
    return target


def validate_output_dir(
    path: str | Path, allowed_roots: list[str | Path] | None = None
) -> Path:
    """Validate an --output directory.

    The resolved directory must stay under the current working
    directory or under an explicit scans directory (the allowed
    roots). A path that escapes both is rejected. The directory
    itself is not created here.
    """
    cwd = Path.cwd().resolve()
    roots = [cwd, (cwd / DEFAULT_SCANS_DIR).resolve()]
    if allowed_roots:
        roots = [Path(root).resolve() for root in allowed_roots]
    target = Path(path)
    if not target.is_absolute():
        target = cwd / target
    target = target.resolve()
    for root in roots:
        if target == root or root in target.parents:
            return target
    raise ValueError(
        f"output directory {str(path)!r} is outside the current working "
        f"directory and the scans directory ({roots[0]}). "
        "Use an output directory under the current working directory."
    )


def write_json_report(directory: str | Path, report: dict) -> Path:
    """Write report.json. Returns the path written."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "report.json"
    with path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
    return path


def render_markdown(report: dict) -> str:
    """Render a report as Markdown, escaping firmware-derived text."""
    esc = html.escape
    lines: list[str] = []
    lines.append("# boardaudit report")
    lines.append("")
    lines.append(f"- File: `{esc(str(report.get('file', '')))}`")
    lines.append(f"- Size: {report.get('size_bytes', 0)} bytes")
    lines.append(f"- SHA-256: `{esc(str(report.get('sha256', '')))}`")
    lines.append(
        f"- Entropy: {report.get('entropy_bits_per_byte', 0)} bits per byte"
    )
    lines.append(f"- Strings: {report.get('string_count', 0)}")
    lines.append(f"- Score: {report.get('score', 0)} / 100")
    lines.append(f"- Risk level: {esc(str(report.get('risk_level', '')))}")
    if report.get("authorized") is not None:
        lines.append(f"- Authorized acquisition: {report.get('authorized')}")
    if report.get("board"):
        lines.append(f"- Board: `{esc(str(report.get('board')))}`")
    if report.get("port"):
        lines.append(f"- Port: `{esc(str(report.get('port')))}`")
    if report.get("kind"):
        lines.append(f"- Kind: `{esc(str(report.get('kind')))}`")
    if report.get("profile_used"):
        lines.append(f"- Profile used: `{esc(str(report.get('profile_used')))}`")
    elif report.get("kind") in ("board", None) and "profile_used" in report:
        lines.append("- Profile used: auto-detection")
    if report.get("device"):
        lines.append(f"- Device: `{esc(str(report.get('device')))}`")
    if report.get("gateway"):
        lines.append(f"- Gateway: `{esc(str(report.get('gateway')))}`")
    if report.get("secret_scan_limit_mb") is not None:
        lines.append(
            f"- Secret scan limit: {report.get('secret_scan_limit_mb')} MiB"
        )
    if report.get("analysis_limit_mb") is not None:
        lines.append(
            f"- Analysis limit: {report.get('analysis_limit_mb')} MiB"
        )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Score | {report.get('score', 0)} / 100 |")
    lines.append(f"| Risk level | {esc(str(report.get('risk_level', '')))} |")
    findings = report.get("findings", [])
    lines.append(f"| Findings | {len(findings)} |")
    for severity in ("critical", "high", "medium", "low"):
        count = sum(
            1 for f in findings if str(f.get("severity")) == severity
        )
        lines.append(f"| {severity.capitalize()} findings | {count} |")
    if report.get("total_files") is not None:
        lines.append(f"| Files analyzed | {report.get('total_files')} |")
        lines.append(f"| Files failed | {len(report.get('failed_files', []))} |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("No secret patterns detected.")
    else:
        for finding in findings:
            line = (
                f"- {esc(str(finding.get('rule')))} "
                f"({esc(str(finding.get('severity', '')))}, "
                f"weight {finding.get('weight')}, "
                f"count {finding.get('count')}): "
                f"`{esc(str(finding.get('preview')))}`"
            )
            lines.append(line)
            if finding.get("remediation"):
                lines.append(
                    f"  Remediation: {esc(str(finding.get('remediation')))}"
                )
    lines.append("")
    if report.get("embedded_formats"):
        lines.append("## Embedded formats")
        lines.append("")
        for entry in report["embedded_formats"]:
            lines.append(
                f"- {esc(str(entry.get('format')))} "
                f"at offset 0x{int(entry.get('offset', 0)):x}"
            )
        lines.append("")
    if report.get("filesystems"):
        lines.append("## Embedded filesystems")
        lines.append("")
        for entry in report["filesystems"]:
            lines.append(
                f"- {esc(str(entry.get('filesystem')))} "
                f"at offset 0x{int(entry.get('offset', 0)):x}"
            )
        lines.append("")
    lines.append("## Partitions")
    lines.append("")
    partitions = report.get("partitions", [])
    if not partitions:
        lines.append("No partition table detected.")
    else:
        for part in partitions:
            line = (
                f"- {esc(str(part.get('name')))} "
                f"offset 0x{int(part.get('offset', 0)):x} "
                f"size 0x{int(part.get('size', 0)):x}"
            )
            if part.get("type_name"):
                line += f" ({esc(str(part.get('type_name')))})"
            if part.get("filesystem") and part.get("filesystem") != "unknown":
                line += f" filesystem {esc(str(part.get('filesystem')))}"
            lines.append(line)
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append(
        "Secret values are redacted in this report. "
        "Only the pattern type, count, and a redacted preview are recorded."
    )
    lines.append("")
    return "\n".join(lines)


def write_markdown_report(directory: str | Path, report: dict) -> Path:
    """Write report.md. Returns the path written."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "report.md"
    path.write_text(render_markdown(report), encoding="utf-8")
    return path


def render_html(report: dict) -> str:
    """Render a report as a self-contained HTML page.

    All firmware-derived text is escaped. No external resources
    are referenced: the page works offline from a local file.
    """
    esc = html.escape
    findings_rows = ""
    for finding in report.get("findings", []):
        findings_rows += (
            "<tr><td>" + esc(str(finding.get("rule"))) + "</td>"
            "<td>" + esc(str(finding.get("severity", ""))) + "</td>"
            "<td>" + esc(str(finding.get("count"))) + "</td>"
            "<td>" + esc(str(finding.get("preview"))) + "</td>"
            "<td>" + esc(str(finding.get("remediation", ""))) + "</td></tr>\n"
        )
    if not findings_rows:
        findings_rows = '<tr><td colspan="5">No secret patterns detected.</td></tr>\n'
    partition_rows = ""
    for part in report.get("partitions", []):
        partition_rows += (
            "<tr><td>" + esc(str(part.get("name"))) + "</td>"
            "<td>" + esc(str(part.get("type_name", part.get("type", "")))) + "</td>"
            "<td>0x" + format(int(part.get("offset", 0)), "x") + "</td>"
            "<td>0x" + format(int(part.get("size", 0)), "x") + "</td>"
            "<td>" + esc(str(part.get("filesystem", ""))) + "</td></tr>\n"
        )
    if not partition_rows:
        partition_rows = '<tr><td colspan="5">No partition table detected.</td></tr>\n'
    file_name = esc(str(report.get("file", report.get("device", ""))))
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<title>boardaudit report</title>\n"
        "<style>body{font-family:sans-serif;max-width:900px;margin:2em auto;"
        "padding:0 1em}table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #ccc;padding:4px 8px;text-align:left}"
        "th{background:#eee}</style>\n</head>\n<body>\n"
        "<h1>boardaudit report</h1>\n"
        f"<p>File: <code>{file_name}</code><br>\n"
        f"Size: {report.get('size_bytes', 0)} bytes<br>\n"
        f"SHA-256: <code>{esc(str(report.get('sha256', '')))}</code><br>\n"
        f"Entropy: {report.get('entropy_bits_per_byte', 0)} bits per byte<br>\n"
        f"Score: {report.get('score', 0)} / 100<br>\n"
        f"Risk level: {esc(str(report.get('risk_level', '')))}</p>\n"
        "<h2>Findings</h2>\n"
        "<table><tr><th>Rule</th><th>Severity</th><th>Count</th>"
        "<th>Preview</th><th>Remediation</th></tr>\n"
        + findings_rows
        + "</table>\n<h2>Partitions</h2>\n"
        "<table><tr><th>Name</th><th>Type</th><th>Offset</th>"
        "<th>Size</th><th>Filesystem</th></tr>\n"
        + partition_rows
        + "</table>\n<p>Secret values are redacted in this report. "
        "Only the pattern type, count, and a redacted preview are recorded.</p>\n"
        "</body>\n</html>\n"
    )


def write_html_report(directory: str | Path, report: dict) -> Path:
    """Write report.html. Returns the path written."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "report.html"
    path.write_text(render_html(report), encoding="utf-8")
    return path


def render_sarif(report: dict) -> dict:
    """Render a report as a SARIF-lite (SARIF 2.1.0) document.

    Each finding becomes one SARIF result with its rule id,
    level, and redacted preview in the message. This is a
    minimal mapping for CI consumption, not a full SARIF
    producer: locations carry the file name only.
    """
    rules: list[dict[str, object]] = []
    results: list[dict[str, object]] = []
    seen_rules: set[str] = set()
    for finding in report.get("findings", []):
        rule_id = str(finding.get("rule"))
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": str(finding.get("description", rule_id))},
                    "fullDescription": {"text": str(finding.get("remediation", ""))},
                    "defaultConfiguration": {
                        "level": SARIF_LEVELS.get(str(finding.get("severity", "low")), "note")
                    },
                }
            )
        results.append(
            {
                "ruleId": rule_id,
                "level": SARIF_LEVELS.get(str(finding.get("severity", "low")), "note"),
                "message": {
                    "text": (
                        f"{rule_id}: count {finding.get('count')}, "
                        f"preview {finding.get('preview')}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(report.get("file", ""))
                            }
                        }
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "boardaudit",
                        "version": str(report.get("tool_version", "")),
                        "informationUri": "https://github.com/DevSecurityMX/boardaudit",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif_report(directory: str | Path, report: dict) -> Path:
    """Write report.sarif. Returns the path written."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "report.sarif"
    with path.open("w", encoding="utf-8") as handle:
        json.dump(render_sarif(report), handle, indent=2, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
    return path


def load_report(scans_dir: str | Path, scan_id: str) -> dict:
    """Load report.json for a scan id from scans_dir."""
    directory = scan_dir(scans_dir, scan_id)
    path = directory / "report.json"
    if not path.is_file():
        raise FileNotFoundError(f"no report found for scan id: {scan_id}")
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"report for scan id {scan_id!r} is not a JSON object")
    return data
