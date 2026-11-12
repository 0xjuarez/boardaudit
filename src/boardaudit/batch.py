"""Batch analysis of many files and firmware diffs.

Batch runs analyze each file with the same profile and rules and
produce one combined report plus the per-file reports. Files are
streamed, never loaded whole into memory beyond the analysis
window, and batch work can run in parallel with a process pool.
Diff compares two firmware files by hash, entropy, strings, and
findings, and reports what changed.
"""

from __future__ import annotations

import fnmatch
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

MAX_BATCH_FILES = 1000
MAX_BATCH_FILE_MB = 64


def collect_files(
    directory: str | Path,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_files: int = 100,
    max_size_mb: int = MAX_BATCH_FILE_MB,
) -> tuple[list[Path], list[str]]:
    """Collect files under directory, filtered by glob and size.

    Returns (files, skipped_reasons). Directories are walked
    recursively. Symlinks are not followed.
    """
    root = Path(directory)
    if not root.is_dir():
        raise ValueError(f"batch directory not found: {root}")
    if max_files < 1 or max_files > MAX_BATCH_FILES:
        raise ValueError(f"max-files must be between 1 and {MAX_BATCH_FILES}")
    if max_size_mb < 1 or max_size_mb > MAX_BATCH_FILE_MB:
        raise ValueError(f"max-size-mb must be between 1 and {MAX_BATCH_FILE_MB}")
    include = include or ["*"]
    exclude = exclude or []
    files: list[Path] = []
    skipped: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        name = path.name
        if not any(fnmatch.fnmatchcase(name, pattern) for pattern in include):
            continue
        if any(fnmatch.fnmatchcase(name, pattern) for pattern in exclude):
            skipped.append(f"{path}: excluded by pattern")
            continue
        size = path.stat().st_size
        if size > max_size_mb * 1024 * 1024:
            skipped.append(
                f"{path}: too large ({size} bytes, limit {max_size_mb} MiB)"
            )
            continue
        files.append(path)
        if len(files) >= max_files:
            skipped.append(f"stopped at max-files={max_files}")
            break
    return files, skipped


def _analyze_one(args: tuple[str, int | None, str | None, str | None]) -> dict:
    """Analyze one file in a worker process. Args must be picklable."""
    from .analysis import analyze_firmware

    path, limit_mb, profile_arg, rules_path = args
    profile = None
    rules = None
    if profile_arg:
        from .profiles import resolve_profile_arg

        profile = resolve_profile_arg(profile_arg)
    if rules_path:
        from .rules import load_rules_file

        rules = load_rules_file(rules_path)
    return analyze_firmware(path, limit_mb=limit_mb, profile=profile, rules=rules)


def batch_analyze(
    files: list[str | Path],
    limit_mb: int | None = None,
    profile: str | None = None,
    rules_path: str | None = None,
    workers: int = 1,
) -> dict[str, object]:
    """Analyze a list of files and return one combined report.

    With workers > 1, analysis runs in a process pool; the default
    of 1 runs sequentially. Failures are recorded per file and do
    not stop the batch.
    """
    if workers < 1:
        raise ValueError("workers must be at least 1")
    if workers > 8:
        raise ValueError("workers must be at most 8")
    args = [
        (str(path), limit_mb, profile, rules_path) for path in files
    ]
    reports: list[dict[str, object]] = []
    failed: list[dict[str, object]] = []
    if workers == 1:
        for item in args:
            try:
                reports.append(_analyze_one(item))
            except (FileNotFoundError, ValueError) as exc:
                failed.append({"file": item[0], "error": str(exc)})
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            for item, result in zip(args, pool.map(_analyze_one, args)):
                if isinstance(result, dict):
                    reports.append(result)
                else:  # pragma: no cover - defensive
                    failed.append({"file": item[0], "error": "unknown error"})
    total_findings = sum(len(r.get("findings", [])) for r in reports)
    severity_counts: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for report in reports:
        for finding in report.get("findings", []):
            severity = str(finding.get("severity", "low"))
            if severity in severity_counts:
                severity_counts[severity] += 1
    max_score = max((int(r.get("score", 0)) for r in reports), default=0)
    return {
        "tool": "boardaudit",
        "kind": "batch",
        "total_files": len(files),
        "analyzed_files": len(reports),
        "failed_files": failed,
        "files": reports,
        "total_findings": total_findings,
        "findings_by_severity": severity_counts,
        "max_score": max_score,
        "findings": [
            finding
            for report in reports
            for finding in report.get("findings", [])
        ],
        "score": max_score,
        "risk_level": reports[0].get("risk_level", "low") if reports else "low",
    }


def diff_files(
    path_a: str | Path,
    path_b: str | Path,
    limit_mb: int | None = None,
) -> dict[str, object]:
    """Compare two firmware files and return a diff report.

    Compares hashes, sizes, entropy, string counts, and findings.
    Findings are compared by rule id: added means present in B
    only, removed means present in A only, changed means present
    in both with a different count.
    """
    from .analysis import analyze_firmware

    report_a = analyze_firmware(path_a, limit_mb=limit_mb)
    report_b = analyze_firmware(path_b, limit_mb=limit_mb)

    def findings_map(report: dict) -> dict[str, dict[str, object]]:
        result: dict[str, dict[str, object]] = {}
        for finding in report.get("findings", []):
            result[str(finding.get("rule"))] = finding
        return result

    map_a = findings_map(report_a)
    map_b = findings_map(report_b)
    added: list[dict[str, object]] = []
    removed: list[dict[str, object]] = []
    changed: list[dict[str, object]] = []
    for rule, finding in map_b.items():
        if rule not in map_a:
            added.append(finding)
        elif int(finding.get("count", 0)) != int(map_a[rule].get("count", 0)):
            changed.append(
                {
                    "rule": rule,
                    "count_a": map_a[rule].get("count"),
                    "count_b": finding.get("count"),
                    "severity": finding.get("severity"),
                }
            )
    for rule, finding in map_a.items():
        if rule not in map_b:
            removed.append(finding)
    return {
        "tool": "boardaudit",
        "kind": "diff",
        "file_a": report_a.get("file"),
        "file_b": report_b.get("file"),
        "sha256_a": report_a.get("sha256"),
        "sha256_b": report_b.get("sha256"),
        "identical": report_a.get("sha256") == report_b.get("sha256"),
        "size_a": report_a.get("size_bytes"),
        "size_b": report_b.get("size_bytes"),
        "entropy_a": report_a.get("entropy_bits_per_byte"),
        "entropy_b": report_b.get("entropy_bits_per_byte"),
        "string_count_a": report_a.get("string_count"),
        "string_count_b": report_b.get("string_count"),
        "score_a": report_a.get("score"),
        "score_b": report_b.get("score"),
        "risk_a": report_a.get("risk_level"),
        "risk_b": report_b.get("risk_level"),
        "findings_added": added,
        "findings_removed": removed,
        "findings_changed": changed,
        "findings": added + removed,
        "score": int(report_b.get("score", 0)),
        "risk_level": report_b.get("risk_level"),
    }
