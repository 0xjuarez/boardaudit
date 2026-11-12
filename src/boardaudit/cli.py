"""Command line interface for boardaudit.

Standard library argparse only, so the core install has no CLI
dependency. All user input is validated before use; no shell is
involved anywhere in this tool.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .acquire import AcquisitionError, scan as acquire_scan
from .analysis import analyze_firmware
from .batch import batch_analyze, collect_files, diff_files
from .boards import get_board, list_boards
from .config import load_config
from .disk import (
    DiskError,
    analyze_disk_image,
    disk_device_scan,
    disk_inventory,
    smart_summary,
)
from .inventory import inventory
from .profiles import (
    ProfileError,
    add_profile_file,
    export_profiles,
    get_profile,
    list_profiles,
    load_profile_file,
    user_profiles_dir,
    write_profile_template,
)
from .report import (
    DEFAULT_SCANS_DIR,
    load_report,
    render_html,
    render_markdown,
    render_sarif,
    severity_threshold_met,
    validate_output_dir,
    validate_scan_id,
    write_html_report,
    write_json_report,
    write_markdown_report,
    write_sarif_report,
)
from .router import (
    analyze_router_firmware,
    list_router_profiles,
    parse_router_config_file,
    router_gateway_scan,
    router_inventory,
)
from .rules import RuleError, load_rules_file, validate_rules_file


def _print_json(data: object) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True))


def _load_config(args: argparse.Namespace) -> dict[str, object]:
    """Load boardaudit.toml, print any warnings, return the config."""
    config_path = getattr(args, "config", None)
    config, warnings = load_config(config_path)
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return config


def _scans_dir(args: argparse.Namespace, config: dict[str, object]) -> str:
    """Resolve the scans/output directory: CLI flag, then config, then default."""
    if getattr(args, "scans_dir", None):
        return str(args.scans_dir)
    return str(config.get("output_dir", DEFAULT_SCANS_DIR))


def _load_rules(args: argparse.Namespace) -> list | None:
    """Load a --rules file, or return None when no --rules was given."""
    rules_path = getattr(args, "rules", None)
    if not rules_path:
        return None
    return load_rules_file(rules_path)


def _render_report(report: dict, fmt: str) -> str:
    if fmt == "md":
        return render_markdown(report)
    if fmt == "html":
        return render_html(report)
    if fmt == "sarif":
        return json.dumps(render_sarif(report), indent=2, ensure_ascii=False, sort_keys=True)
    return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True)


def _write_reports(directory: Path, report: dict, fmt: str = "json") -> None:
    write_json_report(directory, report)
    write_markdown_report(directory, report)
    if fmt == "html":
        write_html_report(directory, report)
    if fmt == "sarif":
        write_sarif_report(directory, report)
    print(f"reports written to {directory}", file=sys.stderr)


def _threshold_exit(report: dict, args: argparse.Namespace) -> int:
    """Exit code 3 when findings reach the severity threshold (CI use)."""
    threshold = getattr(args, "severity_threshold", None)
    if threshold is None:
        return 0
    try:
        if severity_threshold_met(report, threshold):
            print(
                f"error: findings at or above severity {threshold} found",
                file=sys.stderr,
            )
            return 3
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def _cmd_list_boards(_args: argparse.Namespace) -> int:
    for profile in list_boards():
        print(
            f"{profile.board_id:12} {profile.name:12} "
            f"flash={profile.flash_size} app_offset=0x{profile.app_offset:x} "
            f"baud={profile.default_baud} tool={profile.acquisition_tool}"
        )
    return 0


def _cmd_inventory(args: argparse.Namespace) -> int:
    data = inventory()
    if args.format == "json":
        _print_json(data)
    else:
        print(f"System: {data['system']}")
        print("Serial ports:")
        for port in data["serial_ports"]:  # type: ignore[union-attr]
            print(f"  {port['device']}  {port.get('description', '')}")
        print("USB devices:")
        for device in data["usb_devices"]:  # type: ignore[union-attr]
            print(f"  {device}")
        print("Network adapters:")
        for adapter in data["network_adapters"]:  # type: ignore[union-attr]
            print(
                f"  {adapter['name']}  mac={adapter.get('mac', '')}  "
                f"state={adapter.get('state', '')}"
            )
    return 0


def _validated_output_dir(args: argparse.Namespace) -> Path | None:
    """Validate --output before any analysis runs.

    Returns the resolved directory, or None when no --output was
    given. Prints an error and returns None (caller returns 1)
    when the directory is rejected, so a bad output path never
    produces a report on stdout first.
    """
    if not args.output:
        return None
    try:
        return validate_output_dir(args.output)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None


def _cmd_analyze(args: argparse.Namespace) -> int:
    _load_config(args)
    directory = _validated_output_dir(args)
    if directory is None and args.output:
        return 1
    try:
        rules = _load_rules(args)
        files = list(args.firmware)
        if len(files) == 1:
            report = analyze_firmware(
                files[0],
                limit_mb=args.limit_mb,
                profile=getattr(args, "profile", None),
                rules=rules,
            )
        else:
            report = batch_analyze(
                files,
                limit_mb=args.limit_mb,
                profile=getattr(args, "profile", None),
                rules_path=getattr(args, "rules", None),
                workers=getattr(args, "workers", 1),
            )
    except (FileNotFoundError, ValueError, ProfileError, RuleError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(_render_report(report, args.format))
    if directory is not None:
        directory.mkdir(parents=True, exist_ok=True)
        _write_reports(directory, report, args.format)
        if report.get("kind") == "batch":
            for index, file_report in enumerate(report.get("files", [])):  # type: ignore[union-attr]
                subdir = directory / "files" / f"file-{index:02d}"
                _write_reports(subdir, file_report, args.format)
    return _threshold_exit(report, args)


def _cmd_batch(args: argparse.Namespace) -> int:
    _load_config(args)
    directory = _validated_output_dir(args)
    if directory is None and args.output:
        return 1
    try:
        files, skipped = collect_files(
            args.directory,
            include=args.include,
            exclude=args.exclude,
            max_files=args.max_files,
            max_size_mb=args.max_size_mb,
        )
        for note in skipped:
            print(f"note: skipped {note}", file=sys.stderr)
        report = batch_analyze(
            files,
            limit_mb=args.limit_mb,
            profile=getattr(args, "profile", None),
            rules_path=getattr(args, "rules", None),
            workers=args.workers,
        )
    except (FileNotFoundError, ValueError, ProfileError, RuleError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(_render_report(report, args.format))
    if directory is not None:
        directory.mkdir(parents=True, exist_ok=True)
        _write_reports(directory, report, args.format)
        for index, file_report in enumerate(report.get("files", [])):  # type: ignore[union-attr]
            subdir = directory / "files" / f"file-{index:02d}"
            _write_reports(subdir, file_report, args.format)
    return _threshold_exit(report, args)


def _cmd_diff(args: argparse.Namespace) -> int:
    _load_config(args)
    directory = _validated_output_dir(args)
    if directory is None and args.output:
        return 1
    try:
        report = diff_files(args.file_a, args.file_b, limit_mb=args.limit_mb)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(_render_report(report, args.format))
    if directory is not None:
        directory.mkdir(parents=True, exist_ok=True)
        _write_reports(directory, report, args.format)
    return _threshold_exit(report, args)


def _cmd_scan(args: argparse.Namespace) -> int:
    if not args.authorized:
        print(
            "error: hardware dump refused: --authorized is required. "
            "Only dump firmware from devices you own or are authorized to audit.",
            file=sys.stderr,
        )
        return 2
    config = _load_config(args)
    try:
        # Validate the board id early for a clear error message.
        get_board(args.board)
        report = acquire_scan(
            port=args.port,
            board_id=args.board,
            authorized=True,
            scans_dir=_scans_dir(args, config),
            allow_port=args.allow_port,
            baud=args.baud,
        )
    except (AcquisitionError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _print_json(report)
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    config = _load_config(args)
    try:
        validate_scan_id(args.scan_id)
        report = load_report(_scans_dir(args, config), args.scan_id)
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.format == "md":
        print(render_markdown(report))
    else:
        _print_json(report)
    return 0


# --- Profiles commands -----------------------------------------------------


def _cmd_profiles_list(args: argparse.Namespace) -> int:
    try:
        profiles = list_profiles(kind=args.kind)
    except ProfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for profile in profiles:
        print(
            f"{profile.profile_id:20} {profile.kind:8} {profile.name:32} "
            f"flash={profile.flash_size} fs={profile.filesystem or '-'} "
            f"tool={profile.acquisition_tool or profile.interface or '-'}"
        )
    return 0


def _cmd_profiles_show(args: argparse.Namespace) -> int:
    try:
        profile = get_profile(args.profile_id)
    except ProfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _print_json(profile.to_dict())
    return 0


def _cmd_profiles_validate(args: argparse.Namespace) -> int:
    try:
        profile = load_profile_file(args.file)
    except ProfileError as exc:
        print(f"error: invalid profile: {exc}", file=sys.stderr)
        return 1
    print(f"valid profile: {profile.profile_id} ({profile.kind})")
    return 0


def _cmd_profiles_new(args: argparse.Namespace) -> int:
    try:
        target = write_profile_template(args.kind, args.profile_id, args.output)
    except ProfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"profile template written to {target}")
    print("Edit it, validate it with: boardaudit profiles validate " + str(target))
    return 0


def _cmd_profiles_add(args: argparse.Namespace) -> int:
    try:
        target = add_profile_file(args.file, force=args.force)
    except ProfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"profile added to {target}")
    print(f"User profiles live in {user_profiles_dir()}")
    return 0


def _cmd_profiles_export(args: argparse.Namespace) -> int:
    try:
        target = export_profiles(args.output, kind=args.kind)
    except ProfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"profiles exported to {target}")
    return 0


# --- Rules commands --------------------------------------------------------


def _cmd_rules_validate(args: argparse.Namespace) -> int:
    rules, errors = validate_rules_file(args.file)
    if errors:
        for error in errors:
            print(f"error: invalid rules file: {error}", file=sys.stderr)
        return 1
    print(f"valid rules file: {len(rules)} rule(s)")
    for rule in rules:
        print(f"  {rule.name} ({rule.kind}, {rule.severity}, weight {rule.weight})")
    return 0


# --- Router commands -------------------------------------------------------


def _cmd_router_profiles(_args: argparse.Namespace) -> int:
    for profile in list_router_profiles():
        print(
            f"{profile.profile_id:20} {profile.soc:28} "
            f"flash={profile.flash_size} fs={profile.filesystem}"
        )
    return 0


def _cmd_router_inventory(args: argparse.Namespace) -> int:
    data = router_inventory()
    if args.format == "json":
        _print_json(data)
    else:
        print(f"System: {data['system']}")
        print(f"Default gateway: {data['default_gateway'] or 'not found'}")
        print(f"Gateway MAC: {data['gateway_mac'] or 'not found'}")
        print(f"Gateway vendor: {data['gateway_vendor']}")
        print("Interfaces:")
        for adapter in data["interfaces"]:  # type: ignore[union-attr]
            print(
                f"  {adapter['name']}  mac={adapter.get('mac', '')}  "
                f"state={adapter.get('state', '')}"
            )
    return 0


def _cmd_router_analyze(args: argparse.Namespace) -> int:
    _load_config(args)
    directory = _validated_output_dir(args)
    if directory is None and args.output:
        return 1
    try:
        rules = _load_rules(args)
        report = analyze_router_firmware(
            args.firmware,
            limit_mb=args.limit_mb,
            profile=getattr(args, "profile", None),
            rules=rules,
        )
    except (FileNotFoundError, ValueError, ProfileError, RuleError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(_render_report(report, args.format))
    if directory is not None:
        directory.mkdir(parents=True, exist_ok=True)
        _write_reports(directory, report, args.format)
    return _threshold_exit(report, args)


def _cmd_router_config(args: argparse.Namespace) -> int:
    try:
        entries = parse_router_config_file(args.file)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _print_json({"file": args.file, "entries": entries})
    return 0


def _cmd_router_scan(args: argparse.Namespace) -> int:
    if not args.authorized:
        print(
            "error: router gateway scan refused: --authorized is required. "
            "Only scan a gateway you own or are authorized to audit.",
            file=sys.stderr,
        )
        return 2
    try:
        report = router_gateway_scan(args.gateway, authorized=True)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _print_json(report)
    return 0


# --- Disk commands ---------------------------------------------------------


def _cmd_disk_inventory(args: argparse.Namespace) -> int:
    data = disk_inventory()
    if args.format == "json":
        _print_json(data)
    else:
        print(f"System: {data['system']}")
        print("Disks:")
        for disk in data["disks"]:  # type: ignore[union-attr]
            print(
                f"  {disk['device']}  {disk.get('model', '')}  "
                f"size={disk.get('size_bytes', 0)}  "
                f"mounted={disk.get('mounted')}"
            )
    return 0


def _cmd_disk_analyze(args: argparse.Namespace) -> int:
    _load_config(args)
    directory = _validated_output_dir(args)
    if directory is None and args.output:
        return 1
    try:
        rules = _load_rules(args)
        report = analyze_disk_image(
            args.image,
            limit_mb=args.limit_mb,
            profile=getattr(args, "profile", None),
            rules=rules,
            hash_all=args.hash_all,
        )
    except (FileNotFoundError, ValueError, ProfileError, RuleError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(_render_report(report, args.format))
    if directory is not None:
        directory.mkdir(parents=True, exist_ok=True)
        _write_reports(directory, report, args.format)
    return _threshold_exit(report, args)


def _cmd_disk_smart(args: argparse.Namespace) -> int:
    data = smart_summary(args.device)
    _print_json(data)
    return 0


def _cmd_disk_scan(args: argparse.Namespace) -> int:
    if not args.authorized:
        print(
            "error: disk device scan refused: --authorized is required. "
            "Only scan disks you own or are authorized to audit.",
            file=sys.stderr,
        )
        return 2
    if not args.read_only:
        print(
            "error: disk device scan refused: --read-only is required. "
            "boardaudit never opens a block device for writing.",
            file=sys.stderr,
        )
        return 2
    try:
        report = disk_device_scan(
            device=args.device,
            authorized=True,
            read_only=True,
            allow_mounted=args.allow_mounted,
            limit_mb=args.limit_mb,
        )
    except (DiskError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _print_json(report)
    return 0


def _add_common_analyze_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format", choices=["json", "md", "html", "sarif"], default="json"
    )
    parser.add_argument("--output", help="Directory to write report.json and report.md")
    parser.add_argument(
        "--limit-mb",
        type=int,
        default=None,
        help="Limit secret/string analysis to the first N megabytes",
    )
    parser.add_argument("--config", help="Path to a boardaudit.toml config file")
    parser.add_argument("--scans-dir", default=None, help="Scans directory (default: boardaudit-out)")
    parser.add_argument(
        "--profile",
        default=None,
        help="Profile id or profile file path (see 'boardaudit profiles list')",
    )
    parser.add_argument(
        "--rules",
        default=None,
        help="Path to a custom rules file (JSON or TOML)",
    )
    parser.add_argument(
        "--severity-threshold",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Exit with code 3 when findings at or above this severity exist (CI use)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="boardaudit",
        description=(
            "Authorized-use audit for microcontroller boards, routers, "
            "and disks. Read-only acquisition and analysis of devices "
            "you own or are authorized to audit. No exploitation, no "
            "credential extraction, no network attacks."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_boards = sub.add_parser("list-boards", help="List supported board profiles")
    p_boards.set_defaults(func=_cmd_list_boards)

    p_inv = sub.add_parser("inventory", help="Read-only hardware inventory")
    p_inv.add_argument("--format", choices=["text", "json"], default="text")
    p_inv.set_defaults(func=_cmd_inventory)

    p_an = sub.add_parser("analyze", help="Analyze one or more firmware files")
    p_an.add_argument("firmware", nargs="+", help="Path to a firmware binary file")
    p_an.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Parallel workers for multi-file analysis (1-8, default 1)",
    )
    _add_common_analyze_args(p_an)
    p_an.set_defaults(func=_cmd_analyze)

    p_batch = sub.add_parser("batch", help="Analyze all files in a directory")
    p_batch.add_argument("directory", help="Directory to walk recursively")
    p_batch.add_argument("--include", action="append", default=None, help="Filename glob to include (repeatable)")
    p_batch.add_argument("--exclude", action="append", default=None, help="Filename glob to exclude (repeatable)")
    p_batch.add_argument("--max-files", type=int, default=100, help="Maximum files to analyze (default 100)")
    p_batch.add_argument("--max-size-mb", type=int, default=64, help="Maximum file size in MiB (default 64)")
    p_batch.add_argument("--workers", type=int, default=1, help="Parallel workers (1-8, default 1)")
    _add_common_analyze_args(p_batch)
    p_batch.set_defaults(func=_cmd_batch)

    p_diff = sub.add_parser("diff", help="Compare two firmware files")
    p_diff.add_argument("file_a", help="First firmware file")
    p_diff.add_argument("file_b", help="Second firmware file")
    p_diff.add_argument("--format", choices=["json", "md", "html", "sarif"], default="json")
    p_diff.add_argument("--output", help="Directory to write report.json and report.md")
    p_diff.add_argument("--limit-mb", type=int, default=None, help="Limit analysis to the first N megabytes")
    p_diff.add_argument("--config", help="Path to a boardaudit.toml config file")
    p_diff.add_argument("--scans-dir", default=None)
    p_diff.set_defaults(func=_cmd_diff)

    p_scan = sub.add_parser("scan", help="Dump and analyze firmware from a device")
    p_scan.add_argument("--port", required=True, help="Serial port, e.g. /dev/ttyUSB0")
    p_scan.add_argument("--board", required=True, help="Board id, see list-boards")
    p_scan.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you own the device or are authorized to audit it",
    )
    p_scan.add_argument("--allow-port", help="Allow a port not in the discovered list")
    p_scan.add_argument("--baud", type=int, help="Baud rate (default: try 115200-921600)")
    p_scan.add_argument("--scans-dir", default=None)
    p_scan.add_argument("--config", help="Path to a boardaudit.toml config file")
    p_scan.set_defaults(func=_cmd_scan)

    p_rep = sub.add_parser("report", help="Show a saved scan report")
    p_rep.add_argument("scan_id", help="Scan id, e.g. 20261107-120000")
    p_rep.add_argument("--format", choices=["json", "md"], default="json")
    p_rep.add_argument("--scans-dir", default=None)
    p_rep.add_argument("--config", help="Path to a boardaudit.toml config file")
    p_rep.set_defaults(func=_cmd_report)

    # Profiles group
    p_prof = sub.add_parser("profiles", help="Unified device profiles (boards, routers, disks)")
    prof_sub = p_prof.add_subparsers(dest="profiles_command", required=True)

    p_pl = prof_sub.add_parser("list", help="List profiles (built-in plus user profiles)")
    p_pl.add_argument("--kind", choices=["board", "router", "disk"], default=None, help="Filter by kind")
    p_pl.set_defaults(func=_cmd_profiles_list)

    p_ps = prof_sub.add_parser("show", help="Show one profile as JSON")
    p_ps.add_argument("profile_id", help="Profile id, e.g. esp32 or nvme-ssd")
    p_ps.set_defaults(func=_cmd_profiles_show)

    p_pv = prof_sub.add_parser("validate", help="Validate a profile file")
    p_pv.add_argument("file", help="Path to a profile file (.json, .toml, or .yaml)")
    p_pv.set_defaults(func=_cmd_profiles_validate)

    p_pn = prof_sub.add_parser("new", help="Write a starter profile file to edit")
    p_pn.add_argument("profile_id", help="Id for the new profile")
    p_pn.add_argument("--kind", choices=["board", "router", "disk"], required=True)
    p_pn.add_argument("--output", required=True, help="Path for the starter profile file")
    p_pn.set_defaults(func=_cmd_profiles_new)

    p_pa = prof_sub.add_parser("add", help="Validate a profile file and install it as a user profile")
    p_pa.add_argument("file", help="Path to a profile file")
    p_pa.add_argument("--force", action="store_true", help="Overwrite an existing profile with the same id")
    p_pa.set_defaults(func=_cmd_profiles_add)

    p_pe = prof_sub.add_parser("export", help="Export the merged profile catalog as JSON")
    p_pe.add_argument("--output", required=True, help="Path for the exported JSON file")
    p_pe.add_argument("--kind", choices=["board", "router", "disk"], default=None, help="Filter by kind")
    p_pe.set_defaults(func=_cmd_profiles_export)

    # Rules group
    p_rules = sub.add_parser("rules", help="Custom detection rules")
    rules_sub = p_rules.add_subparsers(dest="rules_command", required=True)

    p_rv = rules_sub.add_parser("validate", help="Validate a custom rules file")
    p_rv.add_argument("file", help="Path to a rules file (.json or .toml)")
    p_rv.set_defaults(func=_cmd_rules_validate)

    # Router group
    p_router = sub.add_parser("router", help="Router firmware and gateway audit")
    router_sub = p_router.add_subparsers(dest="router_command", required=True)

    p_r_an = router_sub.add_parser("analyze", help="Analyze a router firmware file")
    p_r_an.add_argument("firmware", help="Path to a router firmware file")
    _add_common_analyze_args(p_r_an)
    p_r_an.set_defaults(func=_cmd_router_analyze)

    p_r_inv = router_sub.add_parser("inventory", help="Read-only LAN inventory")
    p_r_inv.add_argument("--format", choices=["text", "json"], default="text")
    p_r_inv.set_defaults(func=_cmd_router_inventory)

    p_r_scan = router_sub.add_parser(
        "scan", help="Read-only gateway check (one ping, ports 80/443)"
    )
    p_r_scan.add_argument("--gateway", required=True, help="Private LAN gateway IPv4 address")
    p_r_scan.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you own the network or are authorized to audit it",
    )
    p_r_scan.set_defaults(func=_cmd_router_scan)

    p_r_prof = router_sub.add_parser("profiles", help="List router SoC profiles")
    p_r_prof.set_defaults(func=_cmd_router_profiles)

    p_r_cfg = router_sub.add_parser(
        "config", help="Parse a router config file (keys only, secrets redacted)"
    )
    p_r_cfg.add_argument("file", help="Path to a router config file (.conf, .cfg, .ini, UCI)")
    p_r_cfg.set_defaults(func=_cmd_router_config)

    # Disk group
    p_disk = sub.add_parser("disk", help="Disk image and block device audit")
    disk_sub = p_disk.add_subparsers(dest="disk_command", required=True)

    p_d_an = disk_sub.add_parser("analyze", help="Analyze a disk image file")
    p_d_an.add_argument("image", help="Path to a disk image file")
    p_d_an.add_argument(
        "--hash-all",
        action="store_true",
        help="Also hash each partition separately (first 4 MiB of each partition)",
    )
    _add_common_analyze_args(p_d_an)
    p_d_an.set_defaults(func=_cmd_disk_analyze)

    p_d_inv = disk_sub.add_parser("inventory", help="Read-only disk inventory")
    p_d_inv.add_argument("--format", choices=["text", "json"], default="text")
    p_d_inv.set_defaults(func=_cmd_disk_inventory)

    p_d_smart = disk_sub.add_parser(
        "smart", help="Read-only SMART health summary (smartctl -H -A, when available)"
    )
    p_d_smart.add_argument("--device", required=True, help="Block device, e.g. /dev/sdb")
    p_d_smart.set_defaults(func=_cmd_disk_smart)

    p_d_scan = disk_sub.add_parser(
        "scan", help="Read-only scan of a live block device"
    )
    p_d_scan.add_argument("--device", required=True, help="Block device, e.g. /dev/sdb")
    p_d_scan.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you own the disk or are authorized to audit it",
    )
    p_d_scan.add_argument(
        "--read-only",
        action="store_true",
        help="Required: open the device read-only (boardaudit never writes)",
    )
    p_d_scan.add_argument(
        "--allow-mounted",
        action="store_true",
        help="Allow scanning a mounted device (still read-only)",
    )
    p_d_scan.add_argument(
        "--limit-mb",
        type=int,
        default=None,
        help="Limit secret/string analysis to the first N megabytes",
    )
    p_d_scan.set_defaults(func=_cmd_disk_scan)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        code = args.func(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        code = 130
    sys.exit(code)


if __name__ == "__main__":
    main()
