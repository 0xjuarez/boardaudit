"""Report generation and escaping tests."""

import json

from boardaudit.analysis import analyze_firmware
from boardaudit.report import load_report, render_markdown, write_json_report, write_markdown_report


def _report_with_secret(tmp_path):
    data = b"AKIAIOSFODNN7EXAMPLE\x00<script>alert(1)</script>\x00"
    path = tmp_path / "fw.bin"
    path.write_bytes(data)
    return analyze_firmware(path)


def test_json_report_has_no_full_secret(tmp_path):
    report = _report_with_secret(tmp_path)
    out = tmp_path / "out"
    json_path = write_json_report(out, report)
    text = json_path.read_text()
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    parsed = json.loads(text)
    assert parsed["score"] >= 40


def test_markdown_escapes_firmware_text(tmp_path):
    report = _report_with_secret(tmp_path)
    # Inject a malicious-looking label via partitions is not possible
    # through the public API, so check the renderer escapes a crafted value.
    report = dict(report)
    report["file"] = "<script>alert(1)</script>"
    md = render_markdown(report)
    assert "<script>" not in md
    assert "&lt;script&gt;" in md


def test_markdown_report_roundtrip(tmp_path):
    report = _report_with_secret(tmp_path)
    out = tmp_path / "out"
    write_json_report(out, report)
    md_path = write_markdown_report(out, report)
    assert md_path.read_text().startswith("# boardaudit report")
    loaded = load_report(tmp_path, "out")
    assert loaded["sha256"] == report["sha256"]
