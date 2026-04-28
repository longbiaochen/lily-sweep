from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from lily_sweep.models import PatternRule


def _parse_pattern_rules(raw_rules: object) -> list[PatternRule]:
    if isinstance(raw_rules, dict):
        raw_rules = raw_rules.get("pattern_rules", [])
    if not isinstance(raw_rules, list):
        raise ValueError("Pattern rules must be a list or an object with 'pattern_rules'.")

    parsed: list[PatternRule] = []
    for raw_rule in raw_rules:
        parsed.append(
            PatternRule(
                id=raw_rule["id"],
                title=raw_rule["title"],
                severity=raw_rule["severity"],
                category=raw_rule["category"],
                regex=raw_rule["regex"],
                extensions=tuple(raw_rule.get("extensions", ["*"])),
                remediation=raw_rule["remediation"],
            )
        )
    return parsed


def load_pattern_rules(extra_rule_file: str | None = None) -> list[PatternRule]:
    builtin_text = resources.files("lily_sweep").joinpath("builtin_rules.json").read_text(encoding="utf-8")
    rules = _parse_pattern_rules(json.loads(builtin_text))
    if extra_rule_file:
        extra_text = Path(extra_rule_file).read_text(encoding="utf-8")
        rules.extend(_parse_pattern_rules(json.loads(extra_text)))
    return rules
