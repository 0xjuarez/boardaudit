# boardaudit — build summary

Project: boardaudit 0.1.0, MIT license.
Copyright 2026 Jesus Alejandro Juarez Contreras / DevSecurityMX.
Built from scratch in Python, based on a review of the original
DevSecurityMX devsec project (ESP32/ESP8266 firmware dump + analysis,
bash + FastAPI). No code, name, or branding was copied from it.

## What was built

- Python package `boardaudit` (standard library core; pyserial and
  esptool are optional hardware extras). Entry point: `boardaudit`.
- Commands: `boardaudit list-boards`, `boardaudit inventory`,
  `boardaudit analyze <firmware.bin> [--format json|md]`,
  `boardaudit scan --port <port> --board <id> --authorized`,
  `boardaudit report <scan-id>`, `boardaudit --help`,
  `boardaudit --version`.
- Board profiles (data only) for 11 boards: ESP32, ESP32-S2,
  ESP32-S3, ESP32-C3, ESP32-C6, ESP8266, STM32F4, STM32L4, RP2040,
  nRF52840, ATmega328P. Each profile has family, flash size, app
  offset, default baud, and acquisition tool.
- Read-only hardware inventory: serial ports (pyserial when
  available, directory fallback otherwise), USB devices (lsusb on
  Linux, system_profiler on macOS, Get-PnpDevice on Windows), and
  network adapters (ip/ifconfig/Get-NetAdapter). No packet capture,
  no promiscuous mode, no Wi-Fi cracking.
- Pure-Python analysis: SHA-256, entropy, string extraction, ESP
  partition-table parsing at 0x8000, secret-pattern detection with
  redaction (only pattern type, count, and a redacted preview such
  as `AKIA****************` are recorded), and rule-based risk
  scoring (weights per rule, capped at 100; low 0-24, medium 25-49,
  high 50-79, critical 80-100). JSON and Markdown reports, with
  firmware-derived text escaped (`json.dump`, `html.escape`).
- Authorized use only: `scan` refuses to run without
  `--authorized` and records the flag in the report. No
  exploitation, no bypass, no credential extraction, no network
  attacks. No `shell=True`, no `eval`/`exec`, subprocess only with
  argument lists. Scan ids must match `[A-Za-z0-9_-]+`; output
  paths are validated to stay under the scans directory. No sudo,
  no runtime pip install, no git clone, no auto-download. A
  missing acquisition tool is a clear error, never an install.
- Universal installer: `install.sh` (Linux/macOS, venv in
  `~/.local/share/boardaudit/venv`, symlink in `~/.local/bin`,
  idempotent, `--system` for a /usr/local install with sudo,
  `--dry-run`, fails clearly when Python < 3.11 is missing) and
  `install.ps1` (Windows, Python 3.11+ check, venv, PATH guidance).
- Docs: README.md (English, no emojis, no generic AI phrases),
  CONTRIBUTING.md, SECURITY.md, LICENSE (MIT), .gitignore,
  pyproject.toml.

## Files

- `pyproject.toml`, `README.md`, `LICENSE`, `CONTRIBUTING.md`,
  `SECURITY.md`, `.gitignore`, `install.sh`, `install.ps1`,
  `BUILD_SUMMARY.md`
- `src/boardaudit/__init__.py`, `__main__.py`, `cli.py`,
  `boards.py`, `inventory.py`, `analysis.py`, `report.py`,
  `acquire.py`
- `tests/test_redaction.py`, `test_analysis.py`,
  `test_boards.py`, `test_paths.py`, `test_reports.py`,
  `test_inventory.py`

## What was tested (exact commands, results)

All tests were run in this VM (Python 3.12.3, Linux).

1. `bash -n install.sh` — OK.
2. `python3 -m compileall -q src/boardaudit` — OK.
3. Fresh venv, `pip install -e ".[dev]"`, `python -m pytest -q`
   — first run: 26 passed, 1 failed (a wrong expectation in
   `test_extract_strings`: the function returns the full run
   `xxhello`, the test expected `hello`). Fixed the test and a
   setuptools license-table deprecation in `pyproject.toml`.
   Re-run: **27 passed**.
4. `python -m bandit -r src/boardaudit` — 849 lines scanned.
   **0 medium, 0 high. 5 low**, all expected: subprocess import
   and subprocess calls with argument lists (no shell), and one
   try/except fallback in the serial-port listing.
5. Fresh venv, `pip install -e .`:
   - `boardaudit --version` — `boardaudit 0.1.0`
   - `boardaudit --help` — OK
   - `boardaudit list-boards` — 11 boards listed
   - `boardaudit inventory --format json` — returned system,
     serial_ports, usb_devices, network_adapters
6. Generated test firmware (36,864 bytes, ESP partition table
   with a `factory` entry, an AWS example key, a Wi-Fi string,
   and an HTTP URL) and ran
   `boardaudit analyze /tmp/test-fw.bin --format md --output /tmp/boardaudit-e2e-out`
   — score 50/100, risk high, partition `factory` parsed,
   findings redacted (`AKIA****************`). `grep` confirmed
   the full example key does **not** appear in `report.json`
   (count 0).
7. `boardaudit scan --port /dev/ttyUSB0 --board esp32` (no
   `--authorized`) — refused, exit code 2.
   `boardaudit scan --port /dev/ttyUSB0 --board nope --authorized`
   — unknown board, exit code 1.
8. `boardaudit report 20261107-120000 --scans-dir /tmp/ba-test-scans --format md`
   — rendered the saved report. `boardaudit report ../etc`
   — rejected, exit code 1.
9. `./install.sh --dry-run` and `./install.sh --help` — OK.
   Real installer run with `HOME=/tmp/fakehome ./install.sh`
   — installed, `/tmp/fakehome/.local/bin/boardaudit --version`
   returned `boardaudit 0.1.0` and `list-boards` worked.
10. No hardware dump was run (no hardware in the VM).

## Known limitations

- Automatic acquisition in 0.1.0 is implemented only for ESP32
  and ESP8266 through esptool. STM32, RP2040, nRF52840, and
  ATmega328P profiles document their acquisition tool, but
  `scan` refuses them with a message telling the user to obtain
  the image with that tool and run `boardaudit analyze` on it.
- Secret detection is pattern-based. It finds the patterns in
  `analysis.py`; it does not prove a value is a live credential,
  and it cannot find obfuscated or encrypted secrets.
- A report with no findings means no checked patterns were
  found, not that the firmware is safe.
- The risk score is a triage aid, not a proof of exploitability.
- `install.sh --system` uses sudo for system packages and the
  /usr/local install; the default per-user install does not.
- The test fixture uses the AWS documentation example key
  (`AKIAIOSFODNN7EXAMPLE`). It is not a real credential; it is
  used only to test redaction, and the tests assert it never
  appears in a report.
- No real secrets, endpoints, payloads, exploits, or the
  PasPapan finding are included in this project.
- The README does not claim the tool is bug-free or
  vulnerability-free.

## Zip

`~/workspace/your_files/boardaudit/boardaudit.zip` — the project
directory contents, excluding `.venv`, `__pycache__`, and `.git`.
Main README: `~/workspace/projects/boardaudit/README.md`.

---

# boardaudit 0.2.0 — build summary

Upgrade from 0.1.0 to 0.2.0, 2026-11-08. The 0.1.0 record
above is kept as-is. New in 0.2.0: router support, disk / hard
drive support, more advanced shared analysis, and a config
file. MIT license, English docs, no emojis, no generic AI
phrases.

## What was added

- `src/boardaudit/router.py` (new): 7 generic router profiles
  by SoC (MediaTek MT7620/MT7621, Qualcomm Atheros QCA9531/
  QCA9563, Broadcom BCM63xx, Realtek RTL8197/RTL8676); format
  detection by magic (uImage, TRX, SquashFS, JFFS2, UBIFS,
  gzip, LZMA, tar); uImage (64-byte big-endian) and TRX
  (28-byte little-endian, HDR0) header parsers; embedded
  filesystem listing; router-specific redacted findings
  (default-credential patterns, hard-coded admin strings,
  Telnet/SSH service strings, embedded certificates, URLs);
  gateway validation (private LAN IPv4 only; rejects public,
  loopback, link-local, reserved, and unspecified addresses);
  small known-OUI vendor table; read-only LAN inventory
  (default gateway via `ip route`/`route`/`Get-NetRoute`,
  gateway MAC via neighbour/ARP table); gateway scan (one
  ICMP ping, one TCP connect to 80/443, short timeouts).
- `src/boardaudit/disk.py` (new): MBR parsing (0x55AA, 4
  entries, type names) and GPT parsing (EFI PART header at
  LBA1, entries at LBA2, known type GUIDs); filesystem guess
  by magic (NTFS, exFAT, FAT32/16/12, ext2/3/4 via 0x53EF at
  +1080); disk image analysis with streamed SHA-256 and
  entropy, secret detection on the first N MiB only (default
  16 MiB); read-only disk inventory (lsblk --json on Linux,
  diskutil on macOS, Get-Disk on Windows); root-device and
  mounted-device checks; device scan requiring `--authorized`
  and `--read-only`, refusing the system/root disk and mounted
  read-write devices unless `--allow-mounted`, always opening
  the device with `O_RDONLY`.
- `src/boardaudit/config.py` (new): loads `boardaudit.toml`
  or `.boardaudit.toml` from the current directory or an
  explicit `--config` path (tomllib); defaults are output_dir
  `boardaudit-out`, redaction on, risk thresholds medium 25 /
  high 50 / critical 80. A config that sets redaction off is
  ignored with a warning.
- `src/boardaudit/analysis.py`: findings now carry `rule_id`,
  `severity` (weight >= 40 critical, >= 25 high, >= 10
  medium, else low), and `remediation`; new rules
  `default_credential` (30), `telnet_service` (10),
  `ssh_service` (5); added `entropy_by_section`,
  `detect_embedded_formats` (uImage, TRX, SquashFS, JFFS2,
  UBIFS, gzip, LZMA, ZIP, ELF, tar), and `duplicate_strings`
  (secret-like values excluded); `analyze_firmware` accepts
  `limit_mb` and reports `entropy_sections`,
  `embedded_formats`, `duplicate_strings`,
  `analysis_limit_mb`, `analysis_window_bytes`.
- `src/boardaudit/report.py`: added `validate_output_dir`
  (resolved output must stay under the current working
  directory or the scans directory); Markdown rendering now
  covers kind/device/gateway, secret-scan limits, finding
  severity and remediation, embedded formats/filesystems,
  and partition type/filesystem.
- `src/boardaudit/cli.py`: kept all 0.1.0 commands; added
  `--limit-mb`, `--config`, and `--scans-dir`; added `router`
  subcommands (`analyze`, `inventory`, `scan`, `profiles`)
  and `disk` subcommands (`analyze`, `inventory`, `scan`
  with `--device --authorized --read-only [--allow-mounted]
  [--limit-mb]`). `--output` is validated before analysis
  runs, so a rejected output directory no longer prints a
  report first.
- `pyproject.toml`: version 0.2.0, description now covers
  boards, routers, and disks; dev extras now pytest + bandit.
- Docs: README.md (router profiles table, disk support,
  router/disk usage, config file, findings model), SECURITY.md
  (disk and router scan scope), CHANGELOG.md (new, 0.2.0 and
  0.1.0 entries).

## Files added or changed in 0.2.0

- Added: `src/boardaudit/router.py`, `src/boardaudit/disk.py`,
  `src/boardaudit/config.py`, `CHANGELOG.md`,
  `tests/test_router.py`, `tests/test_disk.py`,
  `tests/test_config.py`, `tests/test_advanced.py`
- Changed: `src/boardaudit/analysis.py`,
  `src/boardaudit/report.py`, `src/boardaudit/cli.py`,
  `src/boardaudit/__init__.py`, `pyproject.toml`,
  `README.md`, `SECURITY.md`, `BUILD_SUMMARY.md`

## What was tested (exact commands, results)

All tests were run in this VM (Python 3.12.3, Linux).

1. `bash -n install.sh` — OK.
2. `python3 -m compileall -q src/boardaudit` — OK.
3. Fresh venv, `pip install -e ".[dev]"`,
   `python -m pytest -q` — first run: **60 passed, 7 failed**.
   The failures were four real bugs plus three test-fixture
   issues: GPT UTF-16LE name decoding cut names mid-character
   (split on a double NUL byte pair), the disk window ignored
   `--limit-mb` below 2 MiB, gateway validation accepted the
   unspecified address `0.0.0.0`, and the test fixtures used a
   literal example key that was redacted in transit. All four
   were fixed in the code or the fixtures. Re-run:
   **67 passed**.
4. `python -m pyflakes src/boardaudit/*.py` — clean after
   removing two unused imports.
5. `python -m bandit -r src/boardaudit` — first run: 1 medium
   (a false positive: the string `"0.0.0.0"` in router gateway
   parsing is a route-table value, not a socket bind; marked
   with a `nosec B104` comment), 0 high. Re-run: **0 medium,
   0 high, 7 low**, all expected subprocess import and
   subprocess calls with argument lists (no shell).
6. Fresh venv, `pip install -e .`:
   - `boardaudit --version` — `boardaudit 0.2.0`
   - `boardaudit list-boards` — 11 boards listed
   - `boardaudit inventory --format json` — returned system,
     serial_ports, usb_devices, network_adapters
   - `boardaudit router profiles` — 7 router profiles listed
   - Generated test router firmware (uImage header named
     `e2e-router`, SquashFS magic at 0x1000, Telnet string,
     default-credential string, AWS documentation example key,
     HTTP URL) and ran
     `boardaudit router analyze router.bin --format json
     --output out-router` and `--format md` — uImage header
     parsed, SquashFS listed at 0x1000, score 100/100, risk
     critical, findings with severity and remediation,
     previews redacted (`AKIA****************`).
   - Generated test disk image (4 MiB, MBR with one bootable
     FAT32 partition at LBA 2048, AWS documentation example
     key in the first megabyte) and ran
     `boardaudit disk analyze disk.img --format json --output
     out-disk` and `--format md` — partition parsed
     (FAT32, offset 0x100000, size 0x200000), streamed SHA-256,
     score 40/100, risk medium, secret-scan limit 16 MiB.
   - `boardaudit disk inventory` — listed the VM block
     devices read-only (`/dev/vda`, `/dev/vdb`, `/dev/vdc`,
     `/dev/vdd`, all unmounted).
   - `boardaudit router inventory` — default gateway and
     interfaces listed, gateway MAC not found in this VM.
   - A Python check over all 8 generated report files
     confirmed the full example key appears in **none** of
     them.
7. Negative checks:
   - `boardaudit router scan --gateway 8.8.8.8 --authorized`
     — public gateway rejected, exit code 1.
   - `boardaudit router scan --gateway 192.168.1.1` (no
     `--authorized`) — refused, exit code 2.
   - `boardaudit disk analyze disk.img --output /etc` —
     rejected, exit code 1, and after the fix no report is
     printed before the error.
   - `boardaudit disk scan --device /dev/sdb --read-only`
     (no `--authorized`) — refused, exit code 2.
8. No hardware dump, disk device scan, or router gateway scan
   was run against real hardware.

## Known limitations (0.2.0)

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
- Credential-based router config download, default-password
  login, and brute force are out of scope and not implemented.
- Disk writes of any kind (wipe, format, recovery by writing)
  are not features of this tool.
- The test fixtures use the AWS documentation example key. It
  is not a real credential; it is used only to test redaction,
  and the tests assert it never appears in a report. In the
  test files the key is assembled from parts at runtime.

## Zip

`~/workspace/your_files/boardaudit/boardaudit.zip` — 0.2.0
contents, overwriting the 0.1.0 zip. The zip has a single
top-level folder named `boardaudit/` and every file is inside
it (`boardaudit/README.md`, `boardaudit/src/...`,
`boardaudit/tests/...`, `boardaudit/install.sh`, and so on).
Nothing is loose at the root of the zip. Verified with
`unzip -l`: the first entry is `boardaudit/` and no entry
sits outside that folder. Excludes `.venv`, `__pycache__`,
and `.git`. The same layout applies to the GitHub delivery:
one repository named `boardaudit`, with all files inside the
repo, nothing loose outside it.

---

# boardaudit 0.3.0 — build summary

Upgrade from 0.2.0 to 0.3.0, 2026-11-08. The 0.1.0 and 0.2.0
records above are kept as-is. New in 0.3.0: a unified,
user-extensible profile system for the most common devices,
batch analysis and firmware diff, custom detection rules,
deeper firmware analysis, stronger disk and router analysis,
HTML and SARIF-lite reports, a CI severity-threshold exit
code, and streamed (low-memory) file hashing. MIT license,
English docs, no emojis, no generic AI phrases. Nothing was
pushed to GitHub: the upload is for the parent agent to do
after this build is verified.

## What was added

- `src/boardaudit/profiles.py` (new): one schema for boards,
  routers, and disks. Built-in catalog of 35 profiles: 15
  boards (ESP32, ESP32-S2/S3/C3/C6/H2, ESP8266, STM32F4/L4/H7,
  RP2040, nRF52840, ATmega328P, SAMD21, Teensy 4.1), 13 router
  SoCs (MediaTek MT7620/MT7621/MT7981/MT7986, Qualcomm Atheros
  QCA9531/QCA9563/IPQ4019/IPQ8074, Broadcom BCM63xx/BCM47xx,
  Realtek RTL8197/RTL8676, generic OpenWrt-compatible), and 7
  storage types (SATA HDD/SSD, NVMe SSD, USB flash, SD,
  microSD, eMMC). User profiles load from
  `~/.config/boardaudit/profiles/` and `./profiles/`, override
  built-ins with the same id, and are validated strictly:
  required fields, allowed kinds, ids matching
  `[A-Za-z0-9_-]+`, no shell fragments (including `;` in the
  acquisition tool), no URLs with credentials, no secret
  material. Commands: `profiles list [--kind]`, `profiles
  show <id>`, `profiles validate <file>`, `profiles new <id>
  --kind ... --output <file>`, `profiles add <file> [--force]`,
  `profiles export --output <file>`.
- `src/boardaudit/rules.py` (new): user detection rules in
  JSON or TOML (literal or regex, severity, weight,
  remediation). Patterns capped at 512 characters, nested
  quantifiers rejected, regexes must compile, duplicate names
  rejected. `boardaudit rules validate <file>`; `--rules
  <file>` applies rules to any analysis command. Findings are
  redacted like built-in findings.
- `src/boardaudit/deep.py` (new): ELF header parsing (class,
  endianness, machine, entry point), tar and cpio archive
  listings (names and offsets only), gzip/LZMA inner-content
  identification in a bounded 2 MiB in-memory window, and
  PEM/DER certificate detection reporting only validity dates
  (not_before, not_after, expired, days until expiry).
- `src/boardaudit/batch.py` (new): `collect_files` (recursive
  walk, include/exclude globs, max files, max size),
  `batch_analyze` (combined report plus per-file reports,
  findings by severity, sequential or process-pool workers
  1-8), and `diff_files` (hash, size, entropy, strings,
  scores, findings added/removed/changed by rule id).
- `src/boardaudit/boards.py` and `src/boardaudit/router.py`:
  board and router profiles now come from the unified catalog
  in `profiles.py`; the old `get_board`/`list_boards` and
  `get_router_profile`/`list_router_profiles` APIs are kept.
- `src/boardaudit/analysis.py`: SHA-256 and whole-file entropy
  are now streamed in 1 MiB chunks (files are never loaded
  whole beyond the analysis window); `analyze_firmware` accepts
  `profile` (Profile, id, or file) and `rules`, reports
  `profile_used`/`profile_kind`/`profile_name`,
  `custom_rules_applied`, `elf_binaries`,
  `archive_entries`, and `certificates`; ESP partition-table
  offset can come from a profile extra field.
- `src/boardaudit/router.py`: default SSID and web admin path
  findings; `parse_router_config` / `parse_router_config_file`
  for OpenWrt UCI and `.conf`/`.cfg`/`.ini` files (keys only,
  secret-looking values redacted); `analyze_router_firmware`
  accepts profile and rules and reports deep-analysis fields
  and `config_keys` for config-style files.
- `src/boardaudit/disk.py`: GPT backup-header check (backup
  entry count vs primary header entry count), partition
  overlap and out-of-bounds detection, ext superblock state
  and journal checks, `--hash-all` per-partition SHA-256 (first
  4 MiB window, scope recorded), `parse_smartctl_output` and
  `smart_summary` (read-only `smartctl -H -A`; never a
  self-test), `disk_device_scan` now reports `smart` and
  partition overlaps.
- `src/boardaudit/report.py`: `render_html` (self-contained,
  escaped, no external resources), `render_sarif` (SARIF-lite
  2.1.0: rule id, level, redacted preview, file name),
  `write_html_report` / `write_sarif_report`, Markdown summary
  table (score, risk, findings by severity, batch file counts),
  `max_severity` / `severity_threshold_met`.
- `src/boardaudit/cli.py`: `analyze` takes one or more files
  (several files become a batch report); `batch <directory>`
  and `diff <file-a> <file-b>` commands; `profiles` and `rules`
  command groups; `router config <file>`; `disk smart
  --device`; `--format` now json/md/html/sarif;
  `--profile`, `--rules`, and `--severity-threshold`
  (exit code 3) on analyze/router/disk commands; `--workers`
  on analyze/batch; `--hash-all` on disk analyze.
- `pyproject.toml`, `src/boardaudit/__init__.py`: version 0.3.0.
- Docs: README.md (Profiles section with the exact three-step
  flow to add a device, expanded board/router/disk tables,
  batch/diff/rules/HTML/SARIF/threshold usage), SECURITY.md
  (profiles/rules validation in scope), CHANGELOG.md (new
  0.3.0 entry).

## Files added or changed in 0.3.0

- Added: `src/boardaudit/profiles.py`, `src/boardaudit/rules.py`,
  `src/boardaudit/deep.py`, `src/boardaudit/batch.py`,
  `tests/test_profiles.py`, `tests/test_rules.py`,
  `tests/test_deep.py`, `tests/test_batch.py`,
  `tests/test_disk_advanced.py`, `tests/test_reports_advanced.py`
- Changed: `src/boardaudit/analysis.py`,
  `src/boardaudit/boards.py`, `src/boardaudit/router.py`,
  `src/boardaudit/disk.py`, `src/boardaudit/report.py`,
  `src/boardaudit/cli.py`, `src/boardaudit/__init__.py`,
  `pyproject.toml`, `README.md`, `SECURITY.md`,
  `CHANGELOG.md`, `BUILD_SUMMARY.md`,
  `tests/test_boards.py`, `tests/test_router.py`
  (expected profile sets updated for the expanded catalog)

## What was tested (exact commands, results)

All tests were run in this VM (Python 3.12.3, Linux).

1. `bash -n install.sh` — OK.
2. `python3 -m compileall -q src/boardaudit` — OK.
3. Fresh venv, `pip install -e ".[dev]"`,
   `python -m pytest -q` — first run: **105 passed, 3 failed**.
   The failures were three real bugs, all fixed: certificate
   UTCTime parsing included the trailing `Z` in the digit
   string (now slices digits only); profile validation did not
   reject a semicolon in `acquisition_tool` (now rejected);
   the HTML escaping test asserted on a string the renderer
   does not emit (test corrected to inject the markup through
   the report file name, as the Markdown test does). Re-run:
   **108 passed** (41 new tests).
4. `python -m pyflakes src/boardaudit/*.py` — clean after
   removing three unused imports.
5. `python -m bandit -r src/boardaudit` — **0 medium, 0 high,
   7 low**, all expected subprocess import and subprocess calls
   with argument lists (no shell), plus one try/except pass.
6. Fresh venv, `pip install -e .`:
   - `boardaudit --version` — `boardaudit 0.3.0`
   - `boardaudit profiles list` — 35 profiles (15 boards,
     13 routers, 7 disks); `list-boards` — 15; `router
     profiles` — 13; `profiles list --kind disk` — 7
   - Profiles round-trip with a test HOME:
     `profiles new my-router --kind router --output
     my-router.json` → template written;
     `profiles validate my-router.json` → valid;
     `profiles add my-router.json` → installed under
     `~/.config/boardaudit/profiles/my-router.json`;
     `profiles show my-router` → id and kind confirmed
   - Generated test router firmware (uImage header named
     `e2e-router`, SquashFS at 0x1000, Telnet string,
     default-credential string, default SSID `TP-LINK_AB12`,
     AWS documentation example key, HTTP admin URL) and ran
     `boardaudit router analyze router.bin --profile
     mediatek-mt7621 --format json` — profile recorded,
     score 100/100, risk critical, findings include
     `aws_access_key`, `default_credential`,
     `router_default_credential`, `router_telnet_service`,
     `router_web_admin`, `router_default_ssid`
   - Generated test disk image (4 MiB, GPT with one Linux
     filesystem partition named `root`, FAT32 magic at the
     partition start, backup GPT header with entry count 128,
     AWS documentation example key) and ran
     `boardaudit disk analyze disk.img --hash-all` —
     partition parsed (`root`, FAT32), GPT backup present
     and matching, no overlaps, 1 per-partition hash,
     `aws_access_key` found
   - `boardaudit batch batchdir --include '*.bin' --workers 2`
     — 3 files analyzed, 4 findings, by severity
     critical 1 / high 1 / medium 1 / low 1
   - `boardaudit diff router.bin router-clean.bin` —
     not identical, removed findings `aws_access_key`,
     `default_credential`, `telnet_service`, `http_endpoint`,
     scores 85 vs 0
   - `boardaudit analyze router.bin --format html` and
     `--format sarif` — `report.html` and `report.sarif`
     written alongside `report.json`/`report.md`
   - `--severity-threshold high` on the dirty firmware —
     exit code 3; on the clean firmware — exit code 0
   - `boardaudit router config wireless.conf` — keys
     `ssid` and `key` reported with values `****`
   - A `grep` over all generated report files confirmed the
     full example key appears in **none** of them
   - `boardaudit disk smart --device /dev/vda` — returns
     `{"available": false}` in this VM (no smartctl); no error
7. Negative checks:
   - `boardaudit router scan --gateway 8.8.8.8 --authorized`
     — public gateway rejected, exit code 1
   - `boardaudit disk scan --device /dev/sdb --read-only`
     (no `--authorized`) — refused, exit code 2
   - `boardaudit analyze router.bin --profile nope` —
     unknown profile, exit code 1
   - `boardaudit batch ... --output /tmp/...` (outside cwd) —
     rejected, exit code 1 (existing output validation)
8. Zip verification: the zip was extracted to a clean
   directory, installed with `pip install -e ".[dev]"`,
   and re-tested there — **108 passed**, pyflakes clean,
   bandit 0 medium / 0 high / 7 low, `bash -n install.sh`
   OK, `compileall` OK, `--version` 0.3.0, profiles round-trip
   (`new`/`validate`/`add`) OK, `analyze --profile
   mediatek-mt7621` OK, batch and diff OK. The real installer
   was also run with `HOME=/tmp/ba03-fakehome ./install.sh`
   — installed, `/tmp/ba03-fakehome/.local/bin/boardaudit
   --version` returned `boardaudit 0.3.0`, batch and diff
   worked from the installed binary.
9. No hardware dump, disk device scan, or router gateway scan
   was run against real hardware.

## Known limitations (0.3.0)

- Router firmware analysis is static: it parses headers and
  embedded filesystems and scans strings. It does not unpack
  compressed filesystems to disk or execute firmware.
- Disk secret detection only scans the first N megabytes
  (default 16 MiB). A clean result does not mean the rest of
  the image is free of secrets.
- Batch files are capped at 64 MiB each (the firmware
  analysis limit) and 1000 files per run; `--workers` is
  capped at 8.
- Custom rule regexes are length-capped and nested quantifiers
  are rejected; complex rules may need to be split into
  several simpler rules.
- SARIF output is a minimal mapping (rule id, level, redacted
  preview, file name), not a full SARIF producer.
- GPT parsing accepts any non-zero type GUID as a partition;
  a stray 16-byte value landing on an entry slot parses as an
  unknown partition, which is inherent to the format.
- Secret detection is pattern-based. It cannot find obfuscated
  or encrypted secrets, and it does not prove a value is a live
  credential.
- A report with no findings means no checked patterns were
  found, not that the image is safe.
- Credential-based router config download, default-password
  login, and brute force are out of scope and not implemented.
- Disk writes of any kind (wipe, format, recovery by writing)
  are not features of this tool.
- The test fixtures use the AWS documentation example key. It
  is not a real credential; it is used only to test redaction,
  and the tests assert it never appears in a report. In the
  test files the key is assembled from parts at runtime.

## Zip

`~/workspace/your_files/boardaudit/boardaudit.zip` — 0.3.0
contents, overwriting the 0.2.0 zip. The zip has a single
top-level folder named `boardaudit/` and every file is inside
it. Verified with `unzip -l` and a Python check: first entry
is `boardaudit/`, 52 files total, **zero entries outside
`boardaudit/`** (excludes `.venv`, `__pycache__`, `.git`,
`.pytest_cache`, `*.egg-info`). Nothing was pushed to GitHub;
the upload is for the parent agent to do after this build is
verified.
