"""Advanced analysis tests: entropy sections, embedded formats,
duplicate strings, finding severity/remediation, output validation."""

import gzip

import pytest

from boardaudit.analysis import (
    detect_embedded_formats,
    detect_secrets,
    duplicate_strings,
    entropy_by_section,
    severity_for_weight,
)
from boardaudit.report import validate_output_dir


def test_entropy_by_section():
    data = b"\x00" * 65536 + bytes(range(256)) * 256
    sections = entropy_by_section(data, section_size=65536)
    assert len(sections) == 2
    assert sections[0]["offset"] == 0
    assert sections[0]["entropy_bits_per_byte"] == 0.0
    assert sections[1]["entropy_bits_per_byte"] > 7.0
    assert sections[1]["size"] == 65536


def test_entropy_by_section_bad_size():
    with pytest.raises(ValueError):
        entropy_by_section(b"abc", section_size=0)


def test_detect_embedded_formats():
    data = b"\x00" * 16 + b"hsqs" + b"\x00" * 16 + gzip.compress(b"hello")
    formats = detect_embedded_formats(data)
    names = {entry["format"] for entry in formats}
    assert "squashfs" in names
    assert "gzip" in names
    offsets = {entry["format"]: entry["offset"] for entry in formats}
    assert offsets["squashfs"] == 16


def test_detect_embedded_formats_tar():
    block = bytearray(512)
    block[257:262] = b"ustar"
    formats = detect_embedded_formats(bytes(block))
    assert {"format": "tar", "offset": 0} in formats


def test_duplicate_strings():
    strings = ["hello", "hello", "hello", "world", "world", "unique"]
    duplicates = duplicate_strings(strings, min_count=2)
    assert duplicates[0] == {"string": "hello", "count": 3}
    assert duplicate_strings(strings, min_count=5) == []


# AWS documentation example key, built from parts so the literal
# value is only assembled at runtime. It is not a real credential.
EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def test_duplicate_strings_excludes_secrets():
    strings = [EXAMPLE_KEY] * 5
    assert duplicate_strings(strings, min_count=2) == []


def test_severity_for_weight():
    assert severity_for_weight(40) == "critical"
    assert severity_for_weight(25) == "high"
    assert severity_for_weight(10) == "medium"
    assert severity_for_weight(5) == "low"


def test_findings_have_severity_and_remediation():
    findings = detect_secrets([EXAMPLE_KEY])
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "aws_access_key"
    assert finding["severity"] == "critical"
    assert finding["remediation"]
    assert EXAMPLE_KEY not in str(findings)


def test_validate_output_dir_inside_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = validate_output_dir("report-out")
    assert out == (tmp_path / "report-out").resolve()
    out2 = validate_output_dir(tmp_path / "boardaudit-out" / "scan1")
    assert out2 == (tmp_path / "boardaudit-out" / "scan1").resolve()


def test_validate_output_dir_rejects_escape(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError):
        validate_output_dir("/etc")
    with pytest.raises(ValueError):
        validate_output_dir("../outside")
