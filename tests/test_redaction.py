"""Redaction and secret detection tests."""

from boardaudit.analysis import detect_secrets, extract_strings, redact


def test_redact_aws_key():
    secret = "AKIAIOSFODNN7EXAMPLE"
    preview = redact(secret)
    assert preview == "AKIA****************"
    assert secret not in preview
    assert preview.startswith("AKIA")


def test_redact_short_value():
    assert redact("abc") == "****"
    assert redact("") == "****"


def test_detect_secrets_never_returns_full_secret():
    secret = "AKIAIOSFODNN7EXAMPLE"
    data = b"hello " + secret.encode() + b" world\n"
    strings = extract_strings(data)
    findings = detect_secrets(strings)
    assert findings
    aws = [f for f in findings if f["rule"] == "aws_access_key"]
    assert len(aws) == 1
    assert aws[0]["count"] == 1
    assert secret not in str(findings)
    assert aws[0]["preview"] == "AKIA****************"


def test_detect_generic_assignment_redacts_value():
    strings = ["API_KEY=supersecretvalue123"]
    findings = detect_secrets(strings)
    generic = [f for f in findings if f["rule"] == "generic_secret_assignment"]
    assert generic
    assert "supersecretvalue123" not in str(findings)
    assert generic[0]["preview"].startswith("API_KEY=")


def test_no_findings_for_clean_strings():
    findings = detect_secrets(["hello world", "firmware version 1.2.3"])
    assert findings == []
