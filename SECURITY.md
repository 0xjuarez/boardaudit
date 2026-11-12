# Security policy

## Authorized use only

boardaudit is for auditing devices you own or are authorized to
audit. Do not use it on devices, firmware, disks, or networks
without authorization from the owner. A hardware dump, a disk
device scan, and a router gateway scan each require
`--authorized`, and the report records that flag. A disk device
scan also requires `--read-only` and never writes to the disk.
A router gateway scan only pings once and opens one TCP
connection to ports 80/443 on a private LAN address.

## How to report a vulnerability

If you find a security problem in boardaudit itself, do not open
a public issue and do not include a proof of concept that
exposes a secret or a working exploit.

Send a report to jesjuarez590@gmail.com with:

- A description of the problem and the affected version.
- The steps to reproduce it, with any secrets removed.
- What you expected to happen and what happened instead.

You will receive a confirmation, and the report will be
handled before a public fix is published where that is
appropriate.

## What is in scope

- Command injection, path traversal, or escaping failures in
  boardaudit output.
- Secret values written in full to a report, a log, or standard
  output.
- Acquisition running without `--authorized`, or a tool being
  installed, downloaded, or run as root without explicit user
  action.
- Secret values smuggled in through a user profile or a custom
  rules file: profiles and rules are validated, and findings
  are always redacted.

## What is out of scope

- Problems in firmware images, in esptool, pyserial, or other
  third-party tools. Report those to the relevant project.
- Social engineering or physical access to a device.
- Reports that include real secrets or exploit code.
- Router config download with credentials, default-password
  login, and brute force: boardaudit does not implement them.
- Disk writes of any kind: wiping, formatting, or recovery by
  writing are not features of this tool.
