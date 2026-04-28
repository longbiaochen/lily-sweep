from __future__ import annotations

import json

from lily_sweep.models import Finding, ScanReport, severity_rank


def findings_at_or_above(findings: list[Finding] | tuple[Finding, ...], minimum: str) -> list[Finding]:
    floor = severity_rank(minimum)
    return [finding for finding in findings if severity_rank(finding.severity) >= floor]


def format_text(report: ScanReport) -> str:
    lines = [f"LilySweep scan: {report.root}"]
    counts = report.severity_counts()
    if counts:
        rendered_counts = ", ".join(f"{level}={count}" for level, count in counts.items())
        lines.append(f"Findings: {len(report.findings)} ({rendered_counts})")
    else:
        lines.append("Findings: 0")

    for finding in sorted(report.findings, key=lambda item: (-severity_rank(item.severity), item.location, item.id)):
        location = finding.location
        if finding.line:
            location = f"{location}:{finding.line}"
        lines.append("")
        lines.append(f"[{finding.severity.upper()}] {finding.id} :: {finding.title}")
        lines.append(f"  location: {location}")
        lines.append(f"  category: {finding.category} | scanner: {finding.scanner}")
        lines.append(f"  evidence: {finding.evidence}")
        lines.append(f"  remediation: {finding.remediation}")

    return "\n".join(lines)


def format_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def format_sarif(report: ScanReport) -> str:
    rules_by_id: dict[str, Finding] = {}
    for finding in report.findings:
        rules_by_id.setdefault(finding.id, finding)

    rules = [
        {
            "id": rule_id,
            "name": rule.title,
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.remediation},
            "help": {"text": rule.remediation},
            "defaultConfiguration": {"level": _sarif_level(rule.severity)},
            "properties": {
                "severity": rule.severity,
                "category": rule.category,
                "scanner": rule.scanner,
            },
        }
        for rule_id, rule in sorted(rules_by_id.items())
    ]

    results = [_finding_to_sarif_result(finding) for finding in report.findings]
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LilySweep",
                        "semanticVersion": "0.1.0",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "root": str(report.root),
                    "finding_count": len(report.findings),
                    "severity_counts": report.severity_counts(),
                },
            }
        ],
    }
    return json.dumps(payload, indent=2)


def render_report(report: ScanReport, output_format: str) -> str:
    if output_format == "json":
        return format_json(report)
    if output_format == "sarif":
        return format_sarif(report)
    return format_text(report)


def _finding_to_sarif_result(finding: Finding) -> dict[str, object]:
    physical_location: dict[str, object] = {
        "artifactLocation": {
            "uri": finding.location,
        }
    }
    if finding.line:
        physical_location["region"] = {
            "startLine": finding.line,
        }

    return {
        "ruleId": finding.id,
        "level": _sarif_level(finding.severity),
        "message": {
            "text": f"{finding.title}: {finding.evidence}. Remediation: {finding.remediation}",
        },
        "locations": [
            {
                "physicalLocation": physical_location,
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": finding.fingerprint(),
        },
        "properties": {
            "severity": finding.severity,
            "category": finding.category,
            "scanner": finding.scanner,
            "fingerprint": finding.fingerprint(),
        },
    }


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
