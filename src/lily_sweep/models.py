from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_rank(level: str) -> int:
    return SEVERITY_ORDER.get(level.lower(), -1)


@dataclass(frozen=True)
class PatternRule:
    id: str
    title: str
    severity: str
    category: str
    regex: str
    extensions: tuple[str, ...]
    remediation: str


@dataclass(frozen=True)
class ROSPolicy:
    dangerous_topics: tuple[str, ...] = ()
    dangerous_services: tuple[str, ...] = ()
    dangerous_actions: tuple[str, ...] = ()


@dataclass(frozen=True)
class Suppression:
    id: str | None = None
    location: str | None = None
    line: int | None = None
    evidence_contains: str | None = None
    reason: str = ""


@dataclass(frozen=True)
class ScanConfig:
    exclude_paths: tuple[str, ...] = ()
    ros: ROSPolicy = field(default_factory=ROSPolicy)
    suppressions: tuple[Suppression, ...] = ()


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str
    category: str
    location: str
    line: int | None
    evidence: str
    remediation: str
    scanner: str

    def fingerprint(self) -> str:
        payload = "\0".join(
            (
                self.id,
                self.location,
                str(self.line or ""),
                self.evidence.strip(),
            )
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint(),
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "location": self.location,
            "line": self.line,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "scanner": self.scanner,
        }


@dataclass(frozen=True)
class ScanReport:
    root: Path
    findings: tuple[Finding, ...]

    def severity_counts(self) -> dict[str, int]:
        counts = {level: 0 for level in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return {level: count for level, count in counts.items() if count}

    def highest_severity(self) -> str | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda finding: severity_rank(finding.severity)).severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "severity_counts": self.severity_counts(),
            "finding_count": len(self.findings),
            "highest_severity": self.highest_severity(),
            "findings": [finding.to_dict() for finding in self.findings],
        }
