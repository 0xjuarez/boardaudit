# Changelog

## 0.3.0 — 2026-11-08

### Added

- Unified profile system (`src/boardaudit/profiles.py`): one
  schema for boards, routers, and disks. Built-in catalog now
  covers 35 profiles: 15 boards (ESP32 family, ESP8266,
  STM32F4/L4/H7, RP2040, nRF52840, ATmega328P, SAMD21, Teensy
  4.1), 13 router SoCs (MediaTek MT7620/MT7621/MT7981/MT7986,
  Qualcomm Atheros QCA9531/QCA9563/IPQ4019/IPQ8074, Broadcom
  BCM63xx/BCM47xx, Realtek RTL8197/RTL8676, generic
  OpenWrt-compatible), and 7 storage types (SATA HDD/SSD,
  NVMe SSD, USB flash, SD/microSD, eMMC).
- Custom profiles: `boardaudit profiles list [--kind]`,
  `profiles show <id>`, `profiles validate <file>`,
  `profiles new <id> --kind ... --output <file>`,
  `profiles add <file> [--force]`, and
  `profiles export --output <file>`. User profiles load
  automatically from `~/.config/boardaudit/profiles/` and
  `./profiles/`, override built-ins with the same id, and are
  validated strictly (required fields, allowed kinds, no shell
  fragments, no URLs with credentials, no secrets).
- `boardaudit analyze --profile <id or file>` uses the profile
  for partition-table offsets and filesystem hints and records
  `profile_used` in the report; without a profile,
  auto-detection is used.
- Batch analysis: `boardaudit analyze <file1> <file2> ...` and
  `boardaudit batch <directory>` (recursive, `--include` /
  `--exclude` globs, `--max-files`, `--max-size-mb`,
  `--workers` 1-8), producing one combined report plus
  per-file reports under `files/file-00/`, `files/file-01/`,
  and so on.
- Firmware diff: `boardaudit diff <file-a> <file-b>` compares
  hashes, entropy, strings, scores, and findings (added,
  removed, changed).
- Deeper firmware analysis (`src/boardaudit/deep.py`): ELF
  header parsing (class, endianness, machine, entry point),
  tar and cpio archive listings (names and offsets only),
  gzip/LZMA inner-content identification in a bounded 2 MiB
  window, and PEM/DER certificate detection reporting only
  validity dates.
- Custom detection rules (`src/boardaudit/rules.py`): user
  rules in JSON or TOML (literal or regex, severity,
  remediation), loaded with `--rules <file>`, validated with
  `boardaudit rules validate <file>`. Patterns are capped at
  512 characters and nested quantifiers are rejected.
- Stronger disk analysis: GPT backup-header check, partition
  overlap and out-of-bounds detection, ext superblock state
  and journal checks, `--hash-all` (per-partition SHA-256 over
  the first 4 MiB), and `boardaudit disk smart --device`
  (read-only `smartctl -H -A` health summary; never a
  self-test).
- Stronger router analysis: default SSID and web admin path
  findings, and `boardaudit router config <file>` parsing
  OpenWrt UCI and `.conf`/`.cfg`/`.ini` files (keys only,
  secret-looking values redacted).
- Better reporting: `--format html` (self-contained, escaped,
  no external resources), `--format sarif` (SARIF-lite 2.1.0
  for CI), a summary table in Markdown reports, and
  `--severity-threshold` (exit code 3 when findings at or
  above that severity exist).
- Performance: SHA-256 and whole-file entropy are now
  streamed in 1 MiB chunks; firmware files are never loaded
  whole into memory beyond the analysis window.
- Tests: `tests/test_profiles.py`, `tests/test_rules.py`,
  `tests/test_deep.py`, `tests/test_batch.py`,
  `tests/test_disk_advanced.py`, `tests/test_reports_advanced.py`
  (41 new tests, 108 total). See `BUILD_SUMMARY.md` for the
  exact commands and results.

### Fixed

- Certificate date parsing: UTCTime/GeneralizedTime values
  end in `Z`; the parser now slices the digits before the
  suffix instead of including it.
- GPT backup-header check now compares the backup entry count
  against the primary header entry count, not the number of
  non-empty partitions.
- Removed unused imports flagged by pyflakes.

### Limitations

- Router firmware analysis is static: it parses headers and
  embedded filesystems and scans strings. It does not unpack
  compressed filesystems to disk or execute firmware.
- Disk secret detection only scans the first N megabytes
  (default 16 MiB). A clean result does not mean the rest of
  the image is free of secrets.
- Batch files are capped at 64 MiB each (the firmware
  analysis limit) and 1000 files per run.
- Custom rule regexes are length-capped and nested
  quantifiers are rejected; complex rules may need to be
  split into several simpler rules.
- SARIF output is a minimal mapping (rule id, level, redacted
  preview, file name), not a full SARIF producer.

### Out of scope

- Credential-based router config download, default-password
  login, and brute force.
- Disk writes of any kind: wiping, formatting, and recovery by
  writing.
- Automatic acquisition for routers and disks (only ESP32 /
  ESP8266 acquisition is implemented; see 0.1.0).

## 0.2.0 — 2026-11-08

### Added

- Router support (`src/boardaudit/router.py`):
  - `boardaudit router analyze <firmware-file> [--format json|md]`
    with format detection by magic bytes (uImage, TRX, SquashFS,
    JFFS2, UBIFS, gzip, LZMA, tar), uImage and TRX header parsing,
    embedded filesystem listing, and router-specific findings
    (default-credential patterns, hard-coded admin strings,
    embedded certificates, URLs, Telnet/SSH service strings),
    all with redaction.
  - `boardaudit router inventory`: read-only LAN inventory with
    default gateway, local interfaces, and gateway MAC/vendor
    when available. No scanning of other hosts, no SNMP write,
    no login attempts.
  - `boardaudit router scan --gateway <ip> --authorized`: one
    ICMP ping and one TCP connect to ports 80/443 with short
    timeouts. Private LAN addresses only; public, loopback,
    link-local, reserved, and unspecified addresses are rejected.
  - `boardaudit router profiles`: seven generic profiles by SoC
    (MediaTek MT7620/MT7621, Qualcomm Atheros QCA9531/QCA9563,
    Broadcom BCM63xx, Realtek RTL8197/RTL8676) with flash size,
    filesystem, and acquisition notes. No specific commercial
    router model is claimed.
- Disk / hard drive support (`src/boardaudit/disk.py`):
  - `boardaudit disk analyze <image-file> [--format json|md]`
    with MBR and GPT parsing, partition type/offset/size and
    filesystem guesses (FAT12/16/32, exFAT, NTFS, ext2/3/4),
    streamed SHA-256, entropy, and secret-pattern detection on
    the first N megabytes only (default 16 MiB).
  - `boardaudit disk inventory`: read-only block device listing
    via lsblk (Linux), diskutil (macOS), or Get-Disk (Windows),
    with model, size, type, and mount state.
  - `boardaudit disk scan --device <path> --authorized
    --read-only`: hashes a read-only window of a physical disk.
    Refuses the system/root disk and mounted read-write devices
    unless `--allow-mounted` is also passed. Always opens the
    device read-only (`O_RDONLY`).
- Shared advanced analysis:
  - Entropy by section/offset, file-type detection by magic for
    embedded blobs, and duplicate string analysis.
  - Findings now carry a rule id, a severity (from the rule
    weight), and remediation text in JSON and Markdown reports.
  - `--output` directory option, validated before analysis to
    stay under the current working directory or an explicit
    scans directory.
  - `--limit-mb` option for disk and firmware analysis.
  - Config file support: `boardaudit.toml` / `.boardaudit.toml`
    for the default output directory and risk thresholds.
    Redaction is always on; a config file that tries to disable
    it is ignored with a warning.
- Tests: `tests/test_router.py`, `tests/test_disk.py`,
  `tests/test_config.py`, `tests/test_advanced.py` (40 new
  tests, 67 total). See `BUILD_SUMMARY.md` for the exact
  commands and results.

### Fixed

- GPT partition name decoding: the old split on a double NUL
  byte pair cut UTF-16LE names mid-character. Names are now
  decoded as a full 72-byte UTF-16LE field with trailing NULs
  stripped.
- Disk analysis with `--limit-mb` smaller than 2 MiB now
  respects the limit instead of scanning the full 2 MiB head.
- Gateway validation now also rejects the unspecified address
  `0.0.0.0`.
- `--output` is now validated before analysis runs, so a
  rejected output directory no longer prints a report first.
- Removed unused imports flagged by pyflakes.
- One bandit medium finding (a false positive: the string
  `"0.0.0.0"` in router gateway parsing is a route-table value,
  not a socket bind) is now marked with a `nosec` comment.

### Limitations

- Router firmware analysis is static: it parses headers and
  embedded filesystems and scans strings. It does not unpack
  compressed filesystems or execute firmware.
- Router profiles are generic by SoC. Model-specific profiles
  are planned for a future release, once the exact router
  model/SoC is known.
- Disk secret detection only scans the first N megabytes
  (default 16 MiB). A clean result does not mean the rest of
  the image is free of secrets.
- Disk device scan hashes only the read window and reports
  that window; it does not hash or copy the whole disk.
- Analyzing a live disk can change access times. Imaging to a
  file first is the recommended workflow.
- Secret detection is pattern-based. It cannot find obfuscated
  or encrypted secrets, and it does not prove a value is a live
  credential.
- A report with no findings means no checked patterns were
  found, not that the image is safe.

### Out of scope

- Credential-based router config download, default-password
  login, and brute force.
- Disk writes of any kind: wiping, formatting, and recovery by
  writing.
- Unpacking compressed router filesystems.
- Automatic acquisition for routers and disks (only ESP32 /
  ESP8266 acquisition is implemented; see 0.1.0).

## 0.1.0 — 2026-11-07

First release.

- Python package `boardaudit` (standard library core; pyserial
  and esptool are optional hardware extras). Entry point:
  `boardaudit`.
- Commands: `list-boards`, `inventory`, `analyze`, `scan`,
  `report`, `--help`, `--version`.
- Board profiles for 11 boards: ESP32, ESP32-S2, ESP32-S3,
  ESP32-C3, ESP32-C6, ESP8266, STM32F4, STM32L4, RP2040,
  nRF52840, ATmega328P.
- Read-only hardware inventory: serial ports, USB devices, and
  network adapters.
- Pure-Python firmware analysis: SHA-256, entropy, string
  extraction, ESP partition-table parsing, secret-pattern
  detection with redaction, rule-based risk scoring.
- JSON and Markdown reports with escaping.
- Authorized use only: hardware dumps require `--authorized`.
  No `shell=True`, no `eval`/`exec`, subprocess argument lists
  only, scan ids validated, output paths validated.
- Universal installer: `install.sh` (Linux/macOS) and
  `install.ps1` (Windows).
- Docs: README.md, CONTRIBUTING.md, SECURITY.md, LICENSE (MIT).
