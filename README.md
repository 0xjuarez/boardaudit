# boardaudit

boardaudit is a command line tool for authorized firmware audits of
microcontroller boards, routers, and disks. It reads a firmware
image from a device you own or are authorized to audit, or
analyzes a firmware file or disk image you already have, and
produces a JSON and Markdown report with a SHA-256 hash,
entropy, extracted strings, a partition table when present, and
secret-pattern findings with the values redacted.

Current version: 0.3.0. See `CHANGELOG.md` for what changed.

## What it does

- Lists supported board profiles.
- Inventories serial ports, USB devices, and network adapters on the
  host, read-only.
- Dumps flash from ESP32 and ESP8266 boards through esptool, with
  baud-rate fallback, only when `--authorized` is passed.
- Analyzes a firmware file in pure Python: SHA-256, entropy, string
  extraction, ESP partition-table parsing, and secret-pattern
  detection.
- Writes reports in JSON and Markdown. Secret values are never
  written in full. A finding records the pattern type, the count,
  and a redacted preview such as `AKIA****************`.
- Validates scan ids and output paths so a scan id cannot escape
  the scans directory. `--output` must stay under the current
  working directory or an explicit scans directory.
- Analyzes router firmware in pure Python: format detection by
  magic bytes (uImage, TRX, SquashFS, JFFS2, UBIFS, gzip, LZMA,
  tar), uImage and TRX header parsing, embedded filesystem
  listing, and router-specific findings (default-credential
  patterns, Telnet/SSH service strings) with redaction.
- Reads a router's LAN inventory read-only: default gateway,
  local interfaces, and gateway MAC/vendor when available.
  A gateway check (`router scan`) only pings once and opens one
  TCP connection to ports 80/443, and only for a private LAN
  address, only with `--authorized`.
- Analyzes disk images in pure Python: MBR and GPT partition
  tables, filesystem guesses by magic (FAT12/16/32, exFAT, NTFS,
  ext2/3/4), streamed SHA-256, entropy, and secret-pattern
  detection on the first N megabytes only (default 16 MiB,
  `--limit-mb` to change it).
- Lists block devices read-only (`disk inventory`) and can hash
  a read-only window of a physical disk (`disk scan`) only with
  `--authorized --read-only`. It never writes to a disk.
- Finds entropy by section, embedded formats by magic, and
  duplicate strings. Every finding carries a rule id, a
  severity, a weight, and remediation text.
- Detects ELF binaries by magic and reports their class,
  endianness, and machine from the header; lists tar and cpio
  archive entries by name and offset; identifies the inner
  content of gzip and LZMA streams in a bounded window; and
  detects PEM/DER certificates, reporting only their validity
  dates.
- Analyzes many files at once (`analyze` with several files, or
  `batch` over a directory) and compares two firmware files
  with `diff`. Batch analysis can run in parallel with
  `--workers`.
- Writes reports in JSON, Markdown, self-contained HTML, and
  SARIF-lite. `--severity-threshold` exits with code 3 when
  findings at or above that severity exist, for CI use.
- Reads optional configuration from `boardaudit.toml` or
  `.boardaudit.toml` (default output directory, risk
  thresholds). Redaction is always on; a config file cannot
  turn it off.
- Uses one unified profile catalog for boards, routers, and
  disks, with user profiles that override built-ins. See
  "Profiles" below.

## What it does not do

- No exploitation, no bypass, no credential extraction, and no
  network attacks.
- No packet capture, no promiscuous mode, and no Wi-Fi cracking.
- No automatic installation of tools, no `sudo`, no runtime
  `pip install`, no `git clone`, and no automatic download.
- No web dashboard and no network service. boardaudit is a local
  command line tool.
- No router config download with credentials, no default-password
  login, and no brute force. Those are out of scope.
- No writing to disks: no wipe, no format, no recovery by
  writing. A live disk is only ever opened read-only, and
  imaging to a file first is the recommended workflow.
- No SMART self-tests: `disk smart` only reads health and
  attributes with `smartctl -H -A`.
- It does not prove a firmware image or a disk image is safe. A
  report with no findings means no patterns in the checked list
  were found, not that the image is free of problems.

## Supported boards

| Board | Family | Flash | App offset | Acquisition tool |
| --- | --- | --- | --- | --- |
| ESP32 | ESP32 | 4 MiB | 0x10000 | esptool |
| ESP32-S2 | ESP32 | 4 MiB | 0x10000 | esptool |
| ESP32-S3 | ESP32 | 8 MiB | 0x10000 | esptool |
| ESP32-C3 | ESP32 | 4 MiB | 0x10000 | esptool |
| ESP32-C6 | ESP32 | 4 MiB | 0x10000 | esptool |
| ESP8266 | ESP8266 | 4 MiB | 0x10000 | esptool |
| STM32F4 | STM32 | 1 MiB | 0x08000000 | st-flash |
| STM32L4 | STM32 | 1 MiB | 0x08000000 | st-flash |
| RP2040 | RP2040 | 2 MiB | 0x10000000 | picotool |
| nRF52840 | nRF52 | 1 MiB | 0x00000000 | nrfutil |
| ESP32-H2 | ESP32 | 4 MiB | 0x10000 | esptool |
| STM32H7 | STM32 | 2 MiB | 0x08000000 | st-flash |
| SAMD21 | ARM Cortex-M0+ | 256 KiB | 0x0000 | openocd |
| Teensy 4.1 | ARM Cortex-M7 | 8 MiB | 0x60000000 | teensy_loader_cli |
| ATmega328P | AVR | 32 KiB | 0x0000 | avrdude |

Run `boardaudit list-boards` or `boardaudit profiles list --kind board`
for the current list. Custom boards can be added; see "Profiles".

## Profiles

Profiles are data only: a profile never contains code, shell
commands, or credentials, and validation rejects any profile
that tries to smuggle them in. One catalog covers boards,
routers, and disks. Built-in profiles cover the most common
devices (15 boards, 13 router SoCs, 7 storage types). User
profiles override built-ins with the same id.

```sh
# List every profile, or filter by kind
boardaudit profiles list
boardaudit profiles list --kind disk

# Show one profile
boardaudit profiles show nvme-ssd

# Add a new device in three steps:
# 1. Write a starter profile file and edit it.
boardaudit profiles new my-board --kind board --output my-board.json
# 2. Validate it.
boardaudit profiles validate my-board.json
# 3. Install it as a user profile (~/.config/boardaudit/profiles/).
boardaudit profiles add my-board.json
```

User profiles are also loaded automatically from
`~/.config/boardaudit/profiles/` and from `./profiles/` in the
current directory. A profile file can be JSON, TOML, or YAML
(YAML needs PyYAML). Use `boardaudit profiles export --output
profiles.json` to export the merged catalog.

`boardaudit analyze --profile <id or file>` uses that profile
for partition-table offsets and filesystem hints, and the report
records `profile_used`. Without `--profile`, auto-detection is
used and the report says so.

## Supported router profiles

Router profiles are generic, by SoC. They do not claim support
for a specific commercial router model.

| Profile | SoC | Flash | Filesystem |
| --- | --- | --- | --- |
| mediatek-mt7620 | MediaTek MT7620 | 16 MiB | SquashFS / JFFS2 |
| mediatek-mt7621 | MediaTek MT7621 | 16 MiB | SquashFS / JFFS2 |
| mediatek-mt7981 | MediaTek MT7981 | 32 MiB | SquashFS / UBIFS |
| mediatek-mt7986 | MediaTek MT7986 | 32 MiB | SquashFS / UBIFS |
| qca9531 | Qualcomm Atheros QCA9531 | 16 MiB | SquashFS / JFFS2 |
| qca9563 | Qualcomm Atheros QCA9563 | 16 MiB | SquashFS / JFFS2 |
| qca-ipq4019 | Qualcomm IPQ4019 | 32 MiB | SquashFS / JFFS2 |
| qca-ipq8074 | Qualcomm IPQ8074 | 32 MiB | SquashFS / UBIFS |
| bcm63xx | Broadcom BCM63xx | 16 MiB | SquashFS / JFFS2 |
| bcm47xx | Broadcom BCM47xx | 16 MiB | SquashFS / JFFS2 |
| rtl8197 | Realtek RTL8197 | 16 MiB | SquashFS / JFFS2 |
| rtl8676 | Realtek RTL8676 | 16 MiB | SquashFS / JFFS2 |
| generic-openwrt | Generic OpenWrt-compatible | 16 MiB | SquashFS / JFFS2 |

Run `boardaudit router profiles` for the current list and the
acquisition notes for each SoC. Router firmware analysis also
detects default SSID names and web admin paths, and
`boardaudit router config <file>` parses OpenWrt UCI and
`.conf`/`.cfg`/`.ini` config files, reporting keys only, with
secret-looking values redacted.

## Disk support

`boardaudit disk analyze` works on a disk image file (raw
`.img`, `.dd`, or similar). It parses MBR and GPT, lists
partitions with type, offset, size, and a filesystem guess,
computes a streamed SHA-256, and scans the first 16 MiB for
secret patterns, with redaction. Use `--limit-mb` to change
the scanned window. `boardaudit disk inventory` lists block
devices (lsblk on Linux, diskutil on macOS, Get-Disk on
Windows) with model, size, type, and mount state.

`boardaudit disk scan --device /dev/sdX --authorized
--read-only` hashes a read-only window of a physical disk.
It refuses the system/root disk and any mounted read-write
device unless `--allow-mounted` is also passed, and it always
opens the device read-only (`O_RDONLY`). Analyzing a live
disk can change access times; imaging the disk to a file
first and analyzing the image is the recommended workflow.
`boardaudit disk smart --device /dev/sdb` prints a read-only
SMART health summary (health, temperature, attributes) when
`smartctl` is installed; it never runs a self-test.

Disk image analysis also checks the GPT backup header, detects
partition overlaps and partitions that run past the end of the
image, and reports ext superblock state and journal presence.
`--hash-all` hashes each partition separately over its first
4 MiB window.

| Profile | Type | Interface | Filesystem |
| --- | --- | --- | --- |
| sata-hdd | SATA hard disk drive | SATA | NTFS / exFAT / ext4 |
| sata-ssd | SATA solid-state drive | SATA | NTFS / exFAT / ext4 |
| nvme-ssd | NVMe solid-state drive | NVMe | NTFS / exFAT / ext4 |
| usb-flash | USB flash drive | USB | FAT32 / exFAT |
| sd-card | SD card | SD | FAT32 / exFAT |
| microsd | microSD card | SD | FAT32 / exFAT |
| emmc | eMMC storage | eMMC | ext4 / FAT32 |

## Install

Requirements: Python 3.11 or later.

### From a checkout

```sh
./install.sh
boardaudit --version
```

`install.sh` creates a virtual environment in
`~/.local/share/boardaudit/venv`, installs the package into it,
and links `boardaudit` into `~/.local/bin`. It is idempotent:
running it again reuses the same virtual environment. It does
not use `sudo` unless you pass `--system`, in which case it
installs under `/usr/local` instead.

On Windows, run `install.ps1` from PowerShell. It checks for
Python 3.11 or later, creates a virtual environment, installs
the package, and prints the steps to add the install directory
to PATH.

### With pip

```sh
python3 -m pip install .
# With hardware support (pyserial and esptool):
python3 -m pip install ".[hardware]"
# For development and tests:
python3 -m pip install ".[dev]"
```

The core install needs only the Python standard library. Hardware
support is optional: without pyserial and esptool, `boardaudit
inventory` still works with a directory fallback for serial
ports, and `boardaudit analyze` works on firmware files, but
`boardaudit scan` reports that esptool is missing.

## Usage

```sh
# Show supported boards
boardaudit list-boards

# Read-only hardware inventory
boardaudit inventory
boardaudit inventory --format json

# Analyze a firmware file (no hardware needed)
boardaudit analyze firmware.bin
boardaudit analyze firmware.bin --format md --output ./report-out
boardaudit analyze firmware.bin --format html --output ./report-out
boardaudit analyze firmware.bin --profile esp32-s3
boardaudit analyze firmware.bin --rules my-rules.json
# CI use: exit code 3 when a high or critical finding exists
boardaudit analyze firmware.bin --severity-threshold high

# Analyze several files at once (combined report + per-file reports)
boardaudit analyze firmware-a.bin firmware-b.bin --workers 2

# Analyze a whole directory, recursively
boardaudit batch ./firmware-dir --include '*.bin' --exclude '*test*' --max-files 50 --workers 4

# Compare two firmware files
boardaudit diff firmware-old.bin firmware-new.bin

# Profiles: list, show, create, validate, install, export
boardaudit profiles list
boardaudit profiles list --kind router
boardaudit profiles show nvme-ssd
boardaudit profiles new my-board --kind board --output my-board.json
boardaudit profiles validate my-board.json
boardaudit profiles add my-board.json
boardaudit profiles export --output profiles.json

# Custom detection rules
boardaudit rules validate my-rules.json

# Dump and analyze an ESP32 you own or are authorized to audit.
# --authorized is required; without it the command refuses to run.
boardaudit scan --port /dev/ttyUSB0 --board esp32 --authorized

# Show a saved report
boardaudit report 20261107-120000
boardaudit report 20261107-120000 --format md

# Router firmware analysis (no hardware needed)
boardaudit router profiles
boardaudit router analyze router-firmware.bin
boardaudit router analyze router-firmware.bin --format md --output ./report-out
boardaudit router inventory
# Gateway check: private LAN address only, --authorized required.
boardaudit router scan --gateway 192.168.1.1 --authorized

# Disk image analysis (no hardware needed)
boardaudit disk analyze disk.img
boardaudit disk analyze disk.img --limit-mb 32 --output ./report-out
boardaudit disk analyze disk.img --hash-all
boardaudit disk inventory
boardaudit disk smart --device /dev/sdb
# Physical disk: --authorized and --read-only required.
boardaudit disk scan --device /dev/sdb --authorized --read-only
```

If a serial port is not in the discovered list, `scan` refuses
it. Pass `--allow-port` with the exact port path to allow it
explicitly, for example when the device appears under an unusual
name.

## Output format

A scan writes to `boardaudit-out/<scan-id>/`:

- `dump/firmware.bin` — the dumped firmware image
- `report.json` — the full report
- `report.md` — the same report in Markdown
- `report.html` — the same report as a self-contained HTML page
  (only when `--format html` is used)
- `report.sarif` — SARIF-lite for CI (only when `--format sarif`
  is used)

A batch writes a combined `report.json`/`report.md` plus one
per-file report under `files/file-00/`, `files/file-01/`, and
so on.

`report.json` contains, among other fields:

```json
{
  "tool": "boardaudit",
  "file": "firmware.bin",
  "size_bytes": 4194304,
  "sha256": "…",
  "entropy_bits_per_byte": 7.1,
  "string_count": 1234,
  "partitions": [
    {"name": "factory", "type": 0, "subtype": 0, "offset": 65536, "size": 1048576}
  ],
  "findings": [
    {
      "rule": "aws_access_key",
      "rule_id": "aws_access_key",
      "severity": "critical",
      "weight": 40,
      "count": 1,
      "preview": "AKIA****************",
      "remediation": "Rotate the key, remove it from the firmware image, and move credentials to a provisioned secret store."
    }
  ],
  "score": 40,
  "risk_level": "medium",
  "authorized": true,
  "board": "esp32",
  "port": "/dev/ttyUSB0",
  "scan_id": "20261107-120000"
}
```

Risk scoring is rule-based and documented in the code
(`src/boardaudit/analysis.py`): each finding adds its rule
weight, multiplied by its count, capped at 100. Levels are
low (0-24), medium (25-49), high (50-79), and critical (80-100).
The levels can be changed in `boardaudit.toml`, but the score
itself is a triage aid, not a proof of exploitability.

A report also lists `entropy_sections` (entropy per 64 KiB
section), `embedded_formats` (formats found by magic bytes),
`elf_binaries` (ELF headers found), `archive_entries` (tar/cpio
entries and compressed-stream contents), `certificates`
(validity dates only), and `duplicate_strings` (repeated
strings, with secret-like values excluded). Router reports add
`uimage_header`, `trx_header`, `filesystems`, and `config_keys`;
disk reports add `partitions` with filesystem guesses,
`partition_overlaps`, `gpt_backup`, and `secret_scan_limit_mb`,
the window scanned for secrets. Reports record `profile_used`
when a profile was given, and `custom_rules_applied` when a
rules file was used.

## Configuration

An optional `boardaudit.toml` or `.boardaudit.toml` in the
current working directory, or passed with `--config`, sets
defaults:

```toml
[boardaudit]
output_dir = "boardaudit-out"
redaction = true

[boardaudit.risk_thresholds]
medium = 25
high = 50
critical = 80
```

Redaction is always on. If a config file sets
`redaction = false`, boardaudit ignores it, warns, and keeps
redacting.

## Security model

- Authorized use only. Hardware dumps, disk device scans, and
  router gateway scans require `--authorized`, and the report
  records that flag.
- No `shell=True`, no `eval` or `exec`, and no string
  interpolation into commands. External tools run only with
  argument lists.
- Paths and scan ids are validated. Scan ids must match
  `[A-Za-z0-9_-]+`.
- Report output escapes firmware-derived text. JSON output
  uses `json.dump`; Markdown output uses `html.escape`.
- Secrets are redacted before they reach a report or the
  terminal. Never paste a full secret into an issue, a log, or
  a report.
- The tool binds no network port and runs no server.

See `SECURITY.md` for how to report a vulnerability.

## Tests

```sh
python3 -m pip install ".[dev]"
python3 -m pytest -q
python3 -m compileall src/boardaudit
```

Tests cover redaction, secret detection, JSON escaping,
path-traversal rejection, board profiles, partition parsing,
report generation, router format detection, MBR/GPT parsing,
disk image analysis, gateway validation, config handling,
entropy sections, embedded formats, duplicate strings,
finding severity, unified profiles and custom profiles,
custom rules, ELF/archive/certificate detection, batch
analysis and diff, SMART parsing, GPT backup headers and
partition overlaps, HTML/SARIF rendering, and severity
thresholds. See `BUILD_SUMMARY.md` in the development
checkout for the exact commands run and the results for this
release.

## Contributing

See `CONTRIBUTING.md`.

## License

MIT. See `LICENSE`.
