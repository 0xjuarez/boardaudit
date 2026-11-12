"""Deep analysis tests: ELF headers, tar/cpio listings, certificates."""

import base64
import io
import struct
import tarfile

from boardaudit.deep import (
    detect_certificates,
    list_archive_entries,
    list_cpio_entries,
    list_tar_entries,
    parse_elf,
)


def make_elf64(machine=62, entry=0x400000):
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8,
        2,  # type: executable
        machine,
        1,  # version
        entry,
        0,  # phoff
        0,  # shoff
        0,  # flags
        64, 0, 0, 0, 0, 0,
    )
    return header + b"\x00" * 64


def test_parse_elf_64():
    data = make_elf64()
    parsed = parse_elf(data, 0)
    assert parsed is not None
    assert parsed["class"] == 64
    assert parsed["endianness"] == "little"
    assert parsed["machine"] == "x86-64"
    assert parsed["entry_point"] == 0x400000
    assert parse_elf(b"\x00" * 128, 0) is None
    assert parse_elf(data, 10) is None


def test_parse_elf_32_arm():
    header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8,
        2, 40, 1, 0x8000, 0, 0, 0, 52, 0, 0, 0, 0, 0,
    )
    parsed = parse_elf(header, 0)
    assert parsed is not None
    assert parsed["class"] == 32
    assert parsed["machine"] == "ARM"


def test_list_tar_entries():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in (("a.txt", b"hello"), ("dir/b.bin", b"\x00\x01")):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    data = buf.getvalue()
    entries = list_tar_entries(data, 0)
    assert [e["name"] for e in entries] == ["a.txt", "dir/b.bin"]
    assert entries[0]["container"] == "tar"
    assert list_tar_entries(b"\x00" * 1024, 0) == []


def _cpio_entry(name, content):
    name_bytes = name.encode() + b"\x00"
    fields = [0, 0o100644, 0, 0, 1, 0, len(content), 0, 0, 0, 0, len(name_bytes), 0]
    header = b"070701" + b"".join(f"{f:08x}".encode() for f in fields)
    assert len(header) == 110
    body = header + name_bytes
    body += b"\x00" * ((4 - len(body) % 4) % 4)
    body += content
    body += b"\x00" * ((4 - len(content) % 4) % 4)
    return body


def test_list_cpio_entries():
    data = _cpio_entry("hello.txt", b"hello") + _cpio_entry("TRAILER!!!", b"")
    entries = list_cpio_entries(data, 0)
    assert len(entries) == 1
    assert entries[0]["name"] == "hello.txt"
    assert entries[0]["container"] == "cpio"


def test_list_archive_entries_finds_tar_and_gzip(tmp_path):
    import gzip

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("inner.txt")
        info.size = 5
        tar.addfile(info, io.BytesIO(b"hello"))
    tar_bytes = buf.getvalue()
    # Tar at a 512-byte boundary, plus a gzip stream holding a tar.
    data = b"\x00" * 512 + tar_bytes + gzip.compress(tar_bytes)
    entries = list_archive_entries(data)
    names = [e["name"] for e in entries]
    assert "inner.txt" in names
    gzip_entries = [e for e in entries if e["container"] == "gzip"]
    assert gzip_entries and gzip_entries[0].get("inner") == "tar"


def test_detect_certificates_pem():
    der = (
        b"\x30\x82\x00\x20"
        + b"\x17\x0d" + b"260101000000Z"
        + b"\x17\x0d" + b"270101000000Z"
        + b"\x00" * 8
    )
    pem = (
        b"-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(der)
        + b"\n-----END CERTIFICATE-----\n"
    )
    certs = detect_certificates(pem)
    assert len(certs) == 1
    assert certs[0]["format"] == "pem"
    assert certs[0]["not_before"] == "2026-01-01T00:00:00+00:00"
    assert certs[0]["not_after"] == "2027-01-01T00:00:00+00:00"
    assert certs[0]["expired"] is False
    assert detect_certificates(b"no certificates here") == []
