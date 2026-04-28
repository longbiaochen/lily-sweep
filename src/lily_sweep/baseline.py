from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from lily_sweep.models import Finding, ScanReport


def load_baseline_fingerprints(path: str | None) -> set[str]:
    if not path:
        return set()
    payload = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    findings = payload.get("accepted_findings", [])
    return {finding["fingerprint"] for finding in findings if "fingerprint" in finding}


def build_baseline_payload(report: ScanReport) -> dict[str, object]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(report.root),
        "accepted_findings": [
            {
                "fingerprint": finding.fingerprint(),
                "id": finding.id,
                "severity": finding.severity,
                "location": finding.location,
                "line": finding.line,
                "evidence": finding.evidence,
                "reason": "accepted existing finding",
            }
            for finding in report.findings
        ],
    }


def filter_baselined_findings(findings: list[Finding], fingerprints: set[str]) -> list[Finding]:
    if not fingerprints:
        return findings
    return [finding for finding in findings if finding.fingerprint() not in fingerprints]
