from __future__ import annotations

from fnmatch import fnmatch

from lily_sweep.models import Finding, Suppression


def filter_suppressed_findings(findings: list[Finding], suppressions: tuple[Suppression, ...]) -> list[Finding]:
    if not suppressions:
        return findings
    return [finding for finding in findings if not any(_matches(finding, suppression) for suppression in suppressions)]


def _matches(finding: Finding, suppression: Suppression) -> bool:
    if suppression.id and suppression.id != finding.id:
        return False
    if suppression.location and not fnmatch(finding.location, suppression.location):
        return False
    if suppression.line is not None and suppression.line != finding.line:
        return False
    if suppression.evidence_contains and suppression.evidence_contains not in finding.evidence:
        return False
    return True
