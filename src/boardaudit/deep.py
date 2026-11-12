"""Deep firmware inspection: ELF binaries, archives, certificates.

All parsing is pure Python and read-only. Nothing is executed and
nothing is unpacked to disk: archive listings report names and
offsets only, and compressed streams are decompressed into a
bounded in-memory window (2 MiB) only to identify what they
contain.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import io
import lzma
import re
import struct
from datetime import datetime, timezone

MAX_DECOMPRESS_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 100

ELF_MACHINES: dict[int, str] = {
    3: "x86",
    62: "x86-64",
    40: "ARM",
    183: "AArch64",
    8: "MIPS",
    243: "RISC-V",
    20: "PowerPC",
    21: "PowerPC64",
    43: "SPARC",
    2: "SPARC",
}


def parse_elf(data: bytes, offset: int = 0) -> dict[str, object] | None:
    """Parse an ELF header at offset, or return None if not present.

    Reports class (32/64-bit), endianness, machine, and entry
    point from the header only. The binary is never executed.
    """
    if offset < 0 or len(data) < offset + 52:
        return None
    if data[offset : offset + 4] != b"\x7fELF":
        return None
    elf_class = data[offset + 4]
    elf_data = data[offset + 5]
    if elf_class not in (1, 2) or elf_data not in (1, 2):
        return None
    endian = "little" if elf_data == 1 else "big"
    prefix = "<" if endian == "little" else ">"
    machine = struct.unpack_from(prefix + "H", data, offset + 18)[0]
    if elf_class == 1:
        entry = struct.unpack_from(prefix + "I", data, offset + 24)[0]
    else:
        if len(data) < offset + 64:
            return None
        entry = struct.unpack_from(prefix + "Q", data, offset + 24)[0]
    return {
        "format": "elf",
        "offset": offset,
        "class": 32 if elf_class == 1 else 64,
        "endianness": endian,
        "machine": ELF_MACHINES.get(machine, f"unknown ({machine})"),
        "machine_id": machine,
        "entry_point": entry,
    }


def list_tar_entries(
    data: bytes, offset: int = 0, max_entries: int = MAX_ARCHIVE_ENTRIES
) -> list[dict[str, object]]:
    """List entries of a tar archive at offset (names and offsets only)."""
    entries: list[dict[str, object]] = []
    if offset < 0 or len(data) < offset + 512:
        return entries
    pos = offset
    while pos + 512 <= len(data) and len(entries) < max_entries:
        block = data[pos : pos + 512]
        if block == b"\x00" * 512:
            break
        if block[257:262] != b"ustar":
            break
        name = block[0:100].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        prefix = block[345:500].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        if prefix:
            name = prefix.rstrip("/") + "/" + name
        size_field = block[124:136].split(b"\x00", 1)[0].strip()
        try:
            size = int(size_field.decode("ascii", errors="ignore") or "0", 8)
        except ValueError:
            break
        entries.append({"name": name, "offset": pos, "size": size, "container": "tar"})
        pos += 512 + ((size + 511) // 512) * 512
    return entries


def list_cpio_entries(
    data: bytes, offset: int = 0, max_entries: int = MAX_ARCHIVE_ENTRIES
) -> list[dict[str, object]]:
    """List entries of a newc cpio archive at offset (names only)."""
    entries: list[dict[str, object]] = []
    pos = offset
    while pos + 110 <= len(data) and len(entries) < max_entries:
        magic = data[pos : pos + 6]
        if magic not in (b"070701", b"070702"):
            break
        try:
            fields = [
                int(data[pos + 6 + i * 8 : pos + 14 + i * 8], 16) for i in range(13)
            ]
        except ValueError:
            break
        # fields: ino, mode, uid, gid, nlink, mtime, filesize, devmajor,
        # devminor, rdevmajor, rdevminor, namesize, check.
        file_size = fields[6]
        name_size = fields[11]
        name_start = pos + 110
        name_end = name_start + name_size
        if name_end > len(data):
            break
        name = data[name_start:name_end].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        if name == "TRAILER!!!":
            break
        entries.append({"name": name, "offset": pos, "size": file_size, "container": "cpio"})
        header_end = name_end
        data_start = header_end + ((4 - (header_end % 4)) % 4)
        pos = data_start + file_size + ((4 - (file_size % 4)) % 4)
    return entries


def _decompress_bounded(data: bytes, kind: str) -> bytes:
    """Decompress at most MAX_DECOMPRESS_BYTES of a gzip/LZMA stream."""
    try:
        if kind == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
                return handle.read(MAX_DECOMPRESS_BYTES + 1)[:MAX_DECOMPRESS_BYTES]
        with lzma.LZMAFile(io.BytesIO(data)) as handle:
            return handle.read(MAX_DECOMPRESS_BYTES + 1)[:MAX_DECOMPRESS_BYTES]
    except (OSError, lzma.LZMAError, EOFError):
        return b""


def list_archive_entries(
    data: bytes, max_entries: int = MAX_ARCHIVE_ENTRIES
) -> list[dict[str, object]]:
    """List embedded archive entries found anywhere in the data.

    Tar and cpio entries are listed by name and offset. For gzip
    and LZMA streams, the stream is decompressed into a bounded
    window and the inner content is identified (tar listing or
    ELF header) without writing anything to disk.
    """
    entries: list[dict[str, object]] = []
    # Tar archives at 512-byte block boundaries.
    for block_start in range(0, max(0, len(data) - 512), 512):
        if data[block_start + 257 : block_start + 262] == b"ustar":
            for entry in list_tar_entries(data, block_start, max_entries):
                entry = dict(entry)
                entry["archive_offset"] = block_start
                entries.append(entry)
            break
    # Cpio archives (magic "070701" / "070702").
    for magic in (b"070701", b"070702"):
        start = 0
        while len(entries) < max_entries:
            offset = data.find(magic, start)
            if offset < 0:
                break
            found = list_cpio_entries(data, offset, max_entries - len(entries))
            if found:
                entries.extend(found)
                break
            start = offset + 1
    # Compressed streams: identify the inner content.
    for kind, magic in (("gzip", b"\x1f\x8b"), ("lzma", b"\x5d\x00\x00")):
        start = 0
        count = 0
        while count < 5:
            offset = data.find(magic, start)
            if offset < 0:
                break
            inner = _decompress_bounded(data[offset:], kind)
            info: dict[str, object] = {
                "name": f"<{kind} stream>",
                "offset": offset,
                "size": len(inner),
                "container": kind,
            }
            if inner:
                inner_tar = list_tar_entries(inner, 0, 10)
                if inner_tar:
                    info["inner"] = "tar"
                    info["inner_entries"] = [e["name"] for e in inner_tar[:10]]
                elif parse_elf(inner, 0) is not None:
                    elf = parse_elf(inner, 0)
                    info["inner"] = "elf"
                    if elf is not None:
                        info["inner_machine"] = elf["machine"]
                else:
                    info["inner"] = "unknown"
            entries.append(info)
            count += 1
            start = offset + 1
    entries.sort(key=lambda item: int(item["offset"]))
    return entries[:max_entries]


def _parse_asn1_dates(der: bytes) -> tuple[str | None, str | None]:
    """Scan DER bytes for UTCTime (0x17) and GeneralizedTime (0x18).

    Returns (not_before, not_after) as ISO strings, or None values
    when the dates cannot be parsed. Only the first two date tags
    in order are used.
    """
    dates: list[str] = []
    pos = 0
    while pos + 2 <= len(der) and len(dates) < 2:
        tag = der[pos]
        if tag in (0x17, 0x18):
            length = der[pos + 1]
            if length & 0x80:
                # Long form length: not expected for a date; skip.
                pos += 1
                continue
            value = der[pos + 2 : pos + 2 + length]
            try:
                text = value.decode("ascii")
                if tag == 0x17 and len(text) >= 12:
                    parsed = datetime.strptime(text[:12], "%y%m%d%H%M%S").replace(
                        tzinfo=timezone.utc
                    )
                elif tag == 0x18 and len(text) >= 14:
                    parsed = datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(
                        tzinfo=timezone.utc
                    )
                else:
                    pos += 1
                    continue
                dates.append(parsed.isoformat())
            except (ValueError, UnicodeDecodeError):
                pass
            pos += 2 + length
        else:
            pos += 1
    if len(dates) >= 2:
        return dates[0], dates[1]
    return (dates[0] if dates else None, None)


def detect_certificates(
    data: bytes, max_certs: int = 10
) -> list[dict[str, object]]:
    """Detect PEM and DER certificates and report their validity dates.

    Only the dates are reported, never key material. A PEM block
    is base64-decoded and its DER dates parsed; a DER blob is
    found by its sequence header and parsed the same way.
    """
    certs: list[dict[str, object]] = []
    now = datetime.now(timezone.utc)
    pem_re = re.compile(
        rb"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----"
    )
    for match in pem_re.finditer(data):
        if len(certs) >= max_certs:
            break
        try:
            der = base64.b64decode(match.group(1), validate=False)
        except (binascii.Error, ValueError):
            continue
        not_before, not_after = _parse_asn1_dates(der)
        certs.append(
            _cert_entry("pem", match.start(), not_before, not_after, now)
        )
    # DER certificates: a 0x30 0x82 sequence whose length fits in
    # the remaining data, containing two ASN.1 date tags.
    pos = 0
    while len(certs) < max_certs:
        offset = data.find(b"\x30\x82", pos)
        if offset < 0 or offset + 4 > len(data):
            break
        length = struct.unpack_from(">H", data, offset + 2)[0]
        end = offset + 4 + length
        if end > len(data) or length < 100:
            pos = offset + 1
            continue
        not_before, not_after = _parse_asn1_dates(data[offset:end])
        if not_before is None and not_after is None:
            pos = offset + 1
            continue
        certs.append(_cert_entry("der", offset, not_before, not_after, now))
        pos = end
    certs.sort(key=lambda item: int(item["offset"]))
    return certs


def _cert_entry(
    kind: str,
    offset: int,
    not_before: str | None,
    not_after: str | None,
    now: datetime,
) -> dict[str, object]:
    expired: bool | None = None
    days_left: int | None = None
    if not_after:
        try:
            expiry = datetime.fromisoformat(not_after)
            expired = expiry < now
            days_left = (expiry - now).days
        except ValueError:
            expired = None
    return {
        "format": kind,
        "offset": offset,
        "not_before": not_before,
        "not_after": not_after,
        "expired": expired,
        "days_until_expiry": days_left,
    }
