from __future__ import annotations

import re
from pathlib import Path

from lily_sweep.models import Finding
from lily_sweep.scanners.base import Scanner

AGENT_HINTS = (
    "agent",
    "harness",
    "planner",
    "policy",
    "executor",
    "tool",
    "mission",
)

HARNESS_FILE_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
}

AUTH_HINTS = (
    "auth",
    "token",
    "permission",
    "role",
    "depends(",
    "verify",
    "apikey",
    "api_key",
    "bearer",
)

ACTUATOR_HINTS = (
    "unlock",
    "door",
    "elevator",
    "gripper",
    "arm",
    "cmd_vel",
    "trajectory",
    "forklift",
    "vehicle",
    "start",
    "stop",
)

GUARD_FAMILIES = {
    "missing-human-approval-gate": {
        "title": "Missing human approval gate",
        "severity": "high",
        "category": "harness-guardrail",
        "need": ("human_approval", "approval_gate", "human-in-the-loop", "confirm_action"),
        "remediation": "Add a human approval or policy gate before physical or business-critical actions are executed.",
    },
    "missing-action-dry-run": {
        "title": "Missing dry-run / simulation gate",
        "severity": "high",
        "category": "harness-guardrail",
        "need": ("dry_run", "simulation_only", "preview_action", "plan_only"),
        "remediation": "Support a dry-run path so plans can be reviewed without touching real actuators or production tools.",
    },
    "missing-action-budget": {
        "title": "Missing action budget or rate limit",
        "severity": "medium",
        "category": "harness-guardrail",
        "need": ("rate_limit", "budget", "max_actions", "quota", "velocity_limit"),
        "remediation": "Bound how many actions, retries, or actuator updates the agent can issue within a time window.",
    },
    "missing-emergency-stop-or-rollback": {
        "title": "Missing emergency stop or rollback path",
        "severity": "high",
        "category": "harness-guardrail",
        "need": ("rollback_strategy", "rollback", "undo", "kill_switch", "e_stop", "estop", "safe_stop", "circuit_breaker"),
        "remediation": "Provide an emergency stop or compensating rollback path for unsafe or failed executions.",
    },
}


class HarnessScanner(Scanner):
    name = "harness"

    def scan(self, root: Path, files: list[Path], text_cache: dict[Path, str]) -> list[Finding]:
        findings: list[Finding] = []
        harness_files = [file_path for file_path in files if self._is_harness_file(file_path)]
        harness_cache = {file_path: text_cache[file_path] for file_path in harness_files if file_path in text_cache}
        repo_text = "\n".join(harness_cache.values()).lower()
        if not any(hint in repo_text for hint in AGENT_HINTS):
            return findings

        findings.extend(self._find_unguarded_actuator_routes(root, harness_files, harness_cache))
        findings.extend(self._find_guardrail_gaps(root, repo_text))
        findings.extend(self._find_sim_real_ambiguity(root, harness_files, harness_cache))
        return findings

    def _find_unguarded_actuator_routes(
        self,
        root: Path,
        files: list[Path],
        text_cache: dict[Path, str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        route_pattern = re.compile(
            r'(?:@[\w\.]+\.(?:post|get|put|delete)\(\s*["\']([^"\']+)["\']|'
            r'[\w\.]+\.(?:post|get|put|delete)\(\s*["\']([^"\']+)["\'])',
            flags=re.IGNORECASE,
        )
        for file_path in files:
            if file_path.suffix not in {".py", ".js", ".jsx", ".ts", ".tsx"}:
                continue
            text = text_cache.get(file_path)
            if not text:
                continue
            lowered = text.lower()
            for match in route_pattern.finditer(lowered):
                route = next(group for group in match.groups() if group)
                if not any(keyword in route for keyword in ACTUATOR_HINTS):
                    continue
                window = lowered[match.start(): match.start() + 700]
                if any(token in window for token in AUTH_HINTS):
                    continue
                line_number = lowered.count("\n", 0, match.start()) + 1
                findings.append(
                    Finding(
                        id="unguarded-actuator-endpoint",
                        title="High-risk actuator endpoint lacks a nearby auth guard",
                        severity="high",
                        category="actuator-surface",
                        location=file_path.relative_to(root).as_posix(),
                        line=line_number,
                        evidence=route,
                        remediation="Add authentication, authorization, and intent validation around actuator-facing routes.",
                        scanner=self.name,
                    )
                )
        return findings

    def _find_guardrail_gaps(self, root: Path, repo_text: str) -> list[Finding]:
        findings: list[Finding] = []
        for finding_id, family in GUARD_FAMILIES.items():
            tokens = family["need"]
            if not self._guard_family_missing(repo_text, tokens):
                continue
            findings.append(
                Finding(
                    id=finding_id,
                    title=family["title"],
                    severity=family["severity"],
                    category=family["category"],
                    location=".",
                    line=None,
                    evidence=f"Expected one of: {', '.join(tokens)}",
                    remediation=family["remediation"],
                    scanner=self.name,
                )
            )
        return findings

    def _guard_family_missing(self, repo_text: str, tokens: tuple[str, ...]) -> bool:
        if not any(token in repo_text for token in tokens):
            return True

        for token in tokens:
            if re.search(rf"{re.escape(token)}[\"'\s:_-]{{0,20}}(?:=|:)\s*(false|null|none|\"\"|'')", repo_text):
                return True
        return False

    def _is_harness_file(self, file_path: Path) -> bool:
        if file_path.suffix in HARNESS_FILE_SUFFIXES:
            return True
        return file_path.name.lower() in {".env", "dockerfile"}

    def _find_sim_real_ambiguity(
        self,
        root: Path,
        files: list[Path],
        text_cache: dict[Path, str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        sim_terms = ("sim_mode", "simulation", "gazebo", "mock_robot", "dry_run")
        real_terms = ("real_robot", "hardware", "production", "robot_ip", "actuator_ip")
        for file_path in files:
            text = text_cache.get(file_path)
            if not text:
                continue
            lowered = text.lower()
            if not any(term in lowered for term in sim_terms):
                continue
            if not any(term in lowered for term in real_terms):
                continue
            first_real_term = next(term for term in real_terms if term in lowered)
            line_number = lowered.count("\n", 0, lowered.index(first_real_term)) + 1
            findings.append(
                Finding(
                    id="ambiguous-sim-real-boundary",
                    title="Simulation and real-hardware controls appear mixed",
                    severity="high",
                    category="sim-real-boundary",
                    location=file_path.relative_to(root).as_posix(),
                    line=line_number,
                    evidence="same control surface references both simulation and real-hardware terms",
                    remediation="Separate simulation-only and real-hardware code paths with explicit deployment gating.",
                    scanner=self.name,
                )
            )
        return findings
