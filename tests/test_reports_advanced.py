"""HTML/SARIF reporting, severity threshold, router config parsing,
and profile-driven analysis tests."""

import json

from boardaudit.analysis import analyze_firmware
from boardaudit.report import (
    max_severity,
    render_html,
    render_sarif,
    severity_threshold_met,
)
from boardaudit.router import parse_router_config, parse_router_config_file

EXAMPLE_KEY = b"AKIA" + b"IOSFODNN7EXAMPLE"


def test_render_html_escapes_and_is_self_contained(tmp_path):
    data = b"AKIAIOSFODNN7EXAMPLE\x00"
    path = tmp_path / "fw.bin"
    path.write_bytes(data)
    report = analyze_firmware(path)
    report = dict(report)
    report["file"] = "<script>alert(1)</script>"
    html = render_html(report)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "http://" not in html
    assert html.startswith("<!DOCTYPE html>")
    assert "AKIAIOSFODNN7EXAMPLE" not in html


def test_render_sarif_structure(tmp_path):
    data = EXAMPLE_KEY + b"\x00"
    path = tmp_path / "fw.bin"
    path.write_bytes(data)
    report = analyze_firmware(path)
    sarif = render_sarif(report)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "boardaudit"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "aws_access_key" in rule_ids
    assert run["results"][0]["ruleId"] == "aws_access_key"
    assert run["results"][0]["level"] == "error"
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(sarif)


def test_severity_threshold():
    report = {"findings": [{"severity": "high"}, {"severity": "low"}]}
    assert max_severity(report) == "high"
    assert severity_threshold_met(report, "medium") is True
    assert severity_threshold_met(report, "critical") is False
    assert severity_threshold_met(report, None) is False
    assert max_severity({"findings": []}) == "none"


def test_parse_router_config_uci_and_ini():
    text = (
        "config wifi-device 'radio0'\n"
        "\toption type 'mac80211'\n"
        "\toption channel '6'\n"
        "\t option ssid 'MyHome'\n"
        "\toption key 'supersecretpassword'\n"
        "[wireless]\n"
        "ssid = TP-LINK_AB12\n"
        "password = hunter2hunter2\n"
    )
    entries = parse_router_config(text)
    by_key = {e["key"]: e for e in entries}
    assert by_key["channel"]["value"] == "6"
    assert by_key["ssid"]["value"] == "****"  # secret-looking key redacted
    assert by_key["key"]["value"] == "****"
    assert by_key["password"]["value"] == "****"
    assert "supersecretpassword" not in str(entries)
    assert "hunter2hunter2" not in str(entries)


def test_parse_router_config_file(tmp_path):
    path = tmp_path / "wireless"
    path.write_text("config wifi-iface\n\toption ssid 'HomeNet'\n\toption key 'abc12345'\n")
    entries = parse_router_config_file(path)
    assert entries[0]["section"] == "wifi-iface"
    assert "abc12345" not in str(entries)


def test_analyze_with_custom_profile(tmp_path):
    profile_path = tmp_path / "custom.json"
    profile_path.write_text(json.dumps({
        "id": "my-esp", "kind": "board", "name": "My ESP",
        "family": "ESP32", "flash_size": 4194304, "app_offset": 65536,
        "default_baud": 115200, "acquisition_tool": "esptool",
        "extra": {"partition_table_offset": 32768},
    }))
    data = bytearray(b"\x00" * 0x9000)
    data[0x100:0x100 + 4] = b"test"
    path = tmp_path / "fw.bin"
    path.write_bytes(bytes(data))
    report = analyze_firmware(path, profile=str(profile_path))
    assert report["profile_used"] == "my-esp"
    assert report["profile_kind"] == "board"
    report2 = analyze_firmware(path)
    assert report2["profile_used"] is None


def test_router_default_ssid_finding():
    from boardaudit.router import detect_router_findings

    findings = detect_router_findings(["TP-LINK_AB12", "normal string"])
    rules = {f["rule"] for f in findings}
    assert "router_default_ssid" in rules
    ssid = [f for f in findings if f["rule"] == "router_default_ssid"][0]
    assert ssid["preview"].startswith("TP-L")
    assert "TP-LINK_AB12" not in str(findings)
