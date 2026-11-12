"""Custom rules tests: loading, validation, and application."""

import json

import pytest

from boardaudit.rules import (
    RuleError,
    apply_custom_rules,
    load_rules_file,
    validate_rules_file,
)


def _write_rules(tmp_path, rules):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"rules": rules}))
    return path


def test_load_literal_and_regex_rules(tmp_path):
    path = _write_rules(tmp_path, [
        {"name": "marker", "pattern": "SECRET_MARKER", "kind": "literal",
         "severity": "high", "remediation": "Remove the marker."},
        {"name": "token", "pattern": r"tok_[0-9a-f]{8}", "kind": "regex",
         "severity": "critical", "remediation": "Rotate the token."},
    ])
    rules = load_rules_file(path)
    assert len(rules) == 2
    assert rules[0].weight == 25  # high default
    assert rules[1].weight == 40  # critical default


def test_apply_custom_rules_redacts(tmp_path):
    path = _write_rules(tmp_path, [
        {"name": "marker", "pattern": "SECRET_MARKER", "kind": "literal",
         "severity": "high", "remediation": "Remove it."},
    ])
    rules = load_rules_file(path)
    findings = apply_custom_rules(["xx SECRET_MARKER yy", "nothing"], rules)
    assert len(findings) == 1
    assert findings[0]["rule"] == "custom:marker"
    assert findings[0]["severity"] == "high"
    assert "SECRET_MARKER" not in str(findings)
    assert findings[0]["preview"].startswith("SECR")


def test_rules_validate_reports_errors(tmp_path):
    path = _write_rules(tmp_path, [
        {"name": "bad regex", "pattern": r"([", "kind": "regex", "severity": "low"},
    ])
    rules, errors = validate_rules_file(path)
    assert rules == []
    assert errors
    # A bad name is rejected too.
    path2 = _write_rules(tmp_path, [
        {"name": "bad name!", "pattern": "x", "kind": "literal", "severity": "low"},
    ])
    _, errors2 = validate_rules_file(path2)
    assert errors2
    # Missing file.
    _, errors3 = validate_rules_file(tmp_path / "nope.json")
    assert errors3


def test_rules_reject_nested_quantifier(tmp_path):
    path = _write_rules(tmp_path, [
        {"name": "bomb", "pattern": r"(.*)+", "kind": "regex", "severity": "low"},
    ])
    with pytest.raises(RuleError):
        load_rules_file(path)


def test_rules_reject_long_pattern_and_duplicates(tmp_path):
    path = _write_rules(tmp_path, [
        {"name": "long", "pattern": "x" * 600, "kind": "literal", "severity": "low"},
    ])
    with pytest.raises(RuleError):
        load_rules_file(path)
    path2 = _write_rules(tmp_path, [
        {"name": "dup", "pattern": "a", "kind": "literal", "severity": "low"},
        {"name": "dup", "pattern": "b", "kind": "literal", "severity": "low"},
    ])
    with pytest.raises(RuleError):
        load_rules_file(path2)


def test_rules_toml_format(tmp_path):
    path = tmp_path / "rules.toml"
    path.write_text(
        '[[rules]]\nname = "toml-rule"\npattern = "TOML_MARKER"\n'
        'kind = "literal"\nseverity = "medium"\n'
        'remediation = "Remove it."\n'
    )
    rules = load_rules_file(path)
    assert len(rules) == 1
    assert rules[0].name == "toml-rule"
    findings = apply_custom_rules(["TOML_MARKER here"], rules)
    assert findings[0]["rule"] == "custom:toml-rule"
