"""User-defined detection rules (YARA-like, simple form).

A rules file holds literal-string or regex patterns with a
severity and remediation. Rules are data only: a pattern is
compiled with the standard library ``re`` module and never
executed as code. Patterns are length-capped, and quantified
groups that contain another quantifier (a common cause of
catastrophic backtracking) are rejected.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

RULE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
MAX_PATTERN_LEN = 512
MAX_RULES = 200
SEVERITY_WEIGHTS = {"low": 5, "medium": 10, "high": 25, "critical": 40}
# A quantified group whose body already contains a quantifier,
# e.g. "(.*)+" or "(\w+)+": reject it to avoid backtracking bombs.
_NESTED_QUANTIFIER_RE = re.compile(r"\([^)]*[+*?][^)]*\)[+*]")


class RuleError(Exception):
    """Raised when a rules file is invalid."""


@dataclass(frozen=True)
class CustomRule:
    name: str
    pattern: str
    kind: str  # "literal" or "regex"
    severity: str
    weight: int
    remediation: str
    description: str
    compiled: re.Pattern[str] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "pattern": self.pattern,
            "kind": self.kind,
            "severity": self.severity,
            "weight": self.weight,
            "remediation": self.remediation,
            "description": self.description,
        }


def _validate_rule_data(data: object, index: int) -> CustomRule:
    if not isinstance(data, dict):
        raise RuleError(f"rule {index}: must be a mapping (object)")
    name = data.get("name", "")
    if not isinstance(name, str) or not RULE_NAME_RE.match(name):
        raise RuleError(f"rule {index}: name must match [A-Za-z0-9_-]+")
    pattern = data.get("pattern", "")
    if not isinstance(pattern, str) or not pattern:
        raise RuleError(f"rule {index} ({name}): pattern must be a non-empty string")
    if len(pattern) > MAX_PATTERN_LEN:
        raise RuleError(
            f"rule {index} ({name}): pattern is too long "
            f"(max {MAX_PATTERN_LEN} characters)"
        )
    kind = data.get("kind", "literal")
    if kind not in ("literal", "regex"):
        raise RuleError(f"rule {index} ({name}): kind must be 'literal' or 'regex'")
    severity = data.get("severity", "medium")
    if severity not in SEVERITY_WEIGHTS:
        raise RuleError(
            f"rule {index} ({name}): severity must be one of "
            f"{', '.join(SEVERITY_WEIGHTS)}"
        )
    weight = data.get("weight", SEVERITY_WEIGHTS[severity])
    if isinstance(weight, bool) or not isinstance(weight, int) or not 1 <= weight <= 100:
        raise RuleError(f"rule {index} ({name}): weight must be an integer 1-100")
    remediation = data.get("remediation", "")
    description = data.get("description", "")
    for field_name, value in (("remediation", remediation), ("description", description)):
        if not isinstance(value, str) or len(value) > 2000:
            raise RuleError(f"rule {index} ({name}): {field_name} must be a string (max 2000 chars)")
    if kind == "regex":
        if _NESTED_QUANTIFIER_RE.search(pattern):
            raise RuleError(
                f"rule {index} ({name}): pattern has a nested quantifier "
                "and is rejected to avoid catastrophic backtracking"
            )
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise RuleError(f"rule {index} ({name}): regex does not compile: {exc}") from exc
    else:
        compiled = re.compile(re.escape(pattern))
    return CustomRule(
        name=name,
        pattern=pattern,
        kind=kind,
        severity=severity,
        weight=weight,
        remediation=remediation,
        description=description,
        compiled=compiled,
    )


def _parse_rules_file(path: Path) -> list[object]:
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                rules = raw.get("rules")
            else:
                rules = raw
            if not isinstance(rules, list):
                raise RuleError("rules file must contain a 'rules' list")
            return rules
        if suffix == ".toml":
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
            rules = raw.get("rules")
            if not isinstance(rules, list):
                raise RuleError("rules file must contain a 'rules' list")
            return rules
    except RuleError:
        raise
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        raise RuleError(f"cannot read rules file {path}: {exc}") from exc
    raise RuleError(f"unsupported rules file type: {path.suffix!r} (use .json or .toml)")


def load_rules_file(path: str | Path) -> list[CustomRule]:
    """Load and validate a rules file, returning the rules."""
    file_path = Path(path)
    if not file_path.is_file():
        raise RuleError(f"rules file not found: {file_path}")
    raw_rules = _parse_rules_file(file_path)
    if len(raw_rules) > MAX_RULES:
        raise RuleError(f"rules file has more than {MAX_RULES} rules")
    rules: list[CustomRule] = []
    seen: set[str] = set()
    for index, data in enumerate(raw_rules):
        rule = _validate_rule_data(data, index)
        if rule.name in seen:
            raise RuleError(f"duplicate rule name: {rule.name!r}")
        seen.add(rule.name)
        rules.append(rule)
    return rules


def validate_rules_file(path: str | Path) -> tuple[list[CustomRule], list[str]]:
    """Validate a rules file, returning (rules, errors)."""
    try:
        return load_rules_file(path), []
    except RuleError as exc:
        return [], [str(exc)]


def apply_custom_rules(
    strings: list[str], rules: list[CustomRule]
) -> list[dict[str, object]]:
    """Apply custom rules to extracted strings, with redaction.

    Findings never contain a full matched value: the preview is
    the first 4 characters of the match, the rest replaced by '*'.
    """
    from .analysis import redact

    findings: list[dict[str, object]] = []
    for rule in rules:
        if rule.compiled is None:
            continue
        count = 0
        preview = ""
        for text in strings:
            for match in rule.compiled.finditer(text):
                count += 1
                if not preview:
                    preview = redact(match.group(0))
        if count:
            findings.append(
                {
                    "rule": f"custom:{rule.name}",
                    "rule_id": f"custom:{rule.name}",
                    "description": rule.description or f"Custom rule {rule.name}",
                    "weight": rule.weight,
                    "severity": rule.severity,
                    "remediation": rule.remediation,
                    "count": count,
                    "preview": preview,
                }
            )
    return findings
