from __future__ import annotations

import re
from pathlib import Path

from lily_sweep.models import Finding, PatternRule
from lily_sweep.scanners.base import Scanner


class PatternScanner(Scanner):
    name = "pattern"

    def __init__(self, rules: list[PatternRule]) -> None:
        self.rules = rules

    def scan(self, root: Path, files: list[Path], text_cache: dict[Path, str]) -> list[Finding]:
        findings: list[Finding] = []
        for file_path in files:
            text = text_cache.get(file_path)
            if text is None:
                continue
            relative_path = file_path.relative_to(root).as_posix()
            for rule in self.rules:
                if "*" not in rule.extensions and file_path.suffix not in rule.extensions:
                    continue
                for match in re.finditer(rule.regex, text, flags=re.IGNORECASE | re.MULTILINE):
                    line_number = text.count("\n", 0, match.start()) + 1
                    evidence = text.splitlines()[line_number - 1].strip() if text.splitlines() else match.group(0)
                    findings.append(
                        Finding(
                            id=rule.id,
                            title=rule.title,
                            severity=rule.severity,
                            category=rule.category,
                            location=relative_path,
                            line=line_number,
                            evidence=evidence[:220],
                            remediation=rule.remediation,
                            scanner=self.name,
                        )
                    )
        return findings
