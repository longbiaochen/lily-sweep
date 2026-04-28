from __future__ import annotations

import re
from pathlib import Path

from lily_sweep.models import Finding
from lily_sweep.scanners.base import Scanner

# Subprocess / os.system call openings
_SHELL_SINK_PAT = re.compile(
    r"(?:subprocess\.(?:run|call|Popen|check_output)|os\.system)\s*\(",
    re.IGNORECASE,
)

# HTTP client call openings (requests / httpx)
_HTTP_SINK_PAT = re.compile(
    r"(?:requests\.\w+|httpx\.\w+)\s*\(",
    re.IGNORECASE,
)

# Variable names that suggest LLM or externally-sourced input flowing into a shell sink
_UNTRUSTED_CMD_SOURCES = (
    "llm_response",
    "llm_output",
    "llm_result",
    "agent_response",
    "tool_result",
    "tool_output",
    "prompt",
    "user_input",
    "payload",
    "message",
    "instruction",
)

# Variable names that suggest raw LLM / tool output forwarded to an HTTP actuator call
_UNTRUSTED_TOOL_SOURCES = (
    "tool_result",
    "tool_output",
    "llm_response",
    "llm_output",
    "agent_response",
    "tool_call_result",
    "action_result",
)

# Maximum characters to scan ahead from a sink opening to find a tainted variable.
# 400 chars covers most single-statement and short multi-line argument lists.
_WINDOW = 400


class PromptInjectionScanner(Scanner):
    """Detects patterns where LLM or external input flows unchecked into shell
    execution or actuator HTTP calls."""

    name = "prompt_injection"

    def scan(self, root: Path, files: list[Path], text_cache: dict[Path, str]) -> list[Finding]:
        findings: list[Finding] = []
        for file_path in files:
            if file_path.suffix != ".py":
                continue
            text = text_cache.get(file_path)
            if not text:
                continue
            lowered = text.lower()
            findings.extend(self._scan_shell_sinks(root, file_path, lowered))
            findings.extend(self._scan_http_forwarding(root, file_path, lowered))
        return findings

    def _scan_shell_sinks(
        self, root: Path, file_path: Path, lowered: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in _SHELL_SINK_PAT.finditer(lowered):
            window = lowered[match.start(): match.start() + _WINDOW]
            untrusted = next((v for v in _UNTRUSTED_CMD_SOURCES if v in window), None)
            if not untrusted:
                continue
            line_number = lowered.count("\n", 0, match.start()) + 1
            source_lines = lowered.splitlines()
            evidence = source_lines[line_number - 1].strip() if source_lines else match.group(0)
            findings.append(
                Finding(
                    id="llm-input-to-shell",
                    title="LLM or external input flows unchecked into shell execution",
                    severity="critical",
                    category="prompt-injection",
                    location=file_path.relative_to(root).as_posix(),
                    line=line_number,
                    evidence=evidence[:220],
                    remediation=(
                        "Validate and sanitize all externally-sourced variables before passing them "
                        "to subprocess or os.system. Prefer structured argument lists over shell strings."
                    ),
                    scanner=self.name,
                )
            )
        return findings

    def _scan_http_forwarding(
        self, root: Path, file_path: Path, lowered: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in _HTTP_SINK_PAT.finditer(lowered):
            window = lowered[match.start(): match.start() + _WINDOW]
            untrusted = next((v for v in _UNTRUSTED_TOOL_SOURCES if v in window), None)
            if not untrusted:
                continue
            line_number = lowered.count("\n", 0, match.start()) + 1
            source_lines = lowered.splitlines()
            evidence = source_lines[line_number - 1].strip() if source_lines else match.group(0)
            findings.append(
                Finding(
                    id="unvalidated-tool-call-forwarding",
                    title="Unvalidated LLM tool output forwarded to an HTTP actuator call",
                    severity="high",
                    category="prompt-injection",
                    location=file_path.relative_to(root).as_posix(),
                    line=line_number,
                    evidence=evidence[:220],
                    remediation=(
                        "Validate tool call outputs against an explicit schema or allowlist before "
                        "forwarding them to actuator endpoints. Log the intended action for audit."
                    ),
                    scanner=self.name,
                )
            )
        return findings
