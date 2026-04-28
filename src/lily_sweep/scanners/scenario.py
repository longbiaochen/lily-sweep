from __future__ import annotations

from pathlib import Path

from lily_sweep.models import Finding
from lily_sweep.scanners.base import Scanner

SCENARIO_HINTS = ("scene", "scenario", "world", "map", "mission", "workflow", "task")

HAZARD_GROUPS = {
    "scenario-human-dense-zone": {
        "title": "Scenario contains crowd-dense human zones",
        "severity": "high",
        "category": "operational-scene",
        "keywords": ("crowd", "pedestrian", "public_lobby", "people flow", "human_dense", "staff area"),
        "remediation": "Mark human-dense areas as restricted or approval-gated operating zones.",
    },
    "scenario-access-control": {
        "title": "Scenario exposes access-control affordances",
        "severity": "high",
        "category": "operational-scene",
        "keywords": ("elevator", "door", "badge", "turnstile", "gate"),
        "remediation": "Require explicit policy, identity, and fallback handling before agents may touch access-control surfaces.",
    },
    "scenario-heavy-machinery": {
        "title": "Scenario contains heavy machinery or vehicle interaction",
        "severity": "high",
        "category": "operational-scene",
        "keywords": ("forklift", "vehicle", "agv", "robot arm", "conveyor", "lift"),
        "remediation": "Add no-go zones, coordination protocols, and hard stop boundaries around heavy machinery.",
    },
    "scenario-energy-or-toxic": {
        "title": "Scenario contains energy or toxic hazards",
        "severity": "medium",
        "category": "operational-scene",
        "keywords": ("battery", "high_voltage", "chemical", "flammable", "laser", "toxic"),
        "remediation": "Tag hazardous zones and prevent ordinary task planners from entering them without specialized clearance.",
    },
}


class ScenarioScanner(Scanner):
    name = "scenario"

    def scan(self, root: Path, files: list[Path], text_cache: dict[Path, str]) -> list[Finding]:
        findings: list[Finding] = []
        for file_path in files:
            if not self._looks_like_scenario_file(file_path):
                continue
            text = text_cache.get(file_path)
            if not text:
                continue
            lowered = text.lower()
            for finding_id, group in HAZARD_GROUPS.items():
                keyword = next((term for term in group["keywords"] if term in lowered), None)
                if not keyword:
                    continue
                line_number = lowered.count("\n", 0, lowered.index(keyword)) + 1
                findings.append(
                    Finding(
                        id=finding_id,
                        title=group["title"],
                        severity=group["severity"],
                        category=group["category"],
                        location=file_path.relative_to(root).as_posix(),
                        line=line_number,
                        evidence=keyword,
                        remediation=group["remediation"],
                        scanner=self.name,
                    )
                )
        return findings

    def _looks_like_scenario_file(self, file_path: Path) -> bool:
        parts = [part.lower() for part in file_path.parts]
        joined = "/".join(parts)
        return any(hint in joined for hint in SCENARIO_HINTS)
