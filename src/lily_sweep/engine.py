from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

from lily_sweep.baseline import filter_baselined_findings, load_baseline_fingerprints
from lily_sweep.config import load_scan_config
from lily_sweep.models import Finding, ScanReport
from lily_sweep.rule_loader import load_pattern_rules
from lily_sweep.scanners.harness import HarnessScanner
from lily_sweep.scanners.patterns import PatternScanner
from lily_sweep.scanners.ros_control import RosControlScanner
from lily_sweep.scanners.scenario import ScenarioScanner
from lily_sweep.suppressions import filter_suppressed_findings

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}

SKIP_FILENAMES = {
    "lilysweep.json",
    ".lilysweep.json",
    "lilysweep-baseline.json",
    ".lilysweep-baseline.json",
    "lilysweep.yml",
    "lily-sweep.sarif",
}

MAX_TEXT_FILE_BYTES = 1_500_000


def discover_files(root: Path, exclude_globs: tuple[str, ...] = ()) -> list[Path]:
    if root.is_file():
        return [root]

    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name in SKIP_FILENAMES:
            continue
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if any(fnmatch(relative, pattern) for pattern in exclude_globs):
                continue
            files.append(path)
    return files


def build_text_cache(files: list[Path]) -> dict[Path, str]:
    cache: dict[Path, str] = {}
    for file_path in files:
        try:
            if file_path.stat().st_size > MAX_TEXT_FILE_BYTES:
                continue
            raw = file_path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw:
            continue
        try:
            cache[file_path] = raw.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            continue
    return cache


def scan_path(
    target: Path | str,
    extra_rule_file: str | None = None,
    config_path: str | None = None,
    baseline_path: str | None = None,
) -> ScanReport:
    root = Path(target).expanduser().resolve()
    scan_config = load_scan_config(root, explicit_path=config_path)
    files = discover_files(root, exclude_globs=scan_config.exclude_paths)
    text_cache = build_text_cache(files)
    scanners = (
        PatternScanner(load_pattern_rules(extra_rule_file)),
        HarnessScanner(),
        RosControlScanner(scan_config.ros),
        ScenarioScanner(),
    )

    dedupe: set[tuple[str, str, int | None, str]] = set()
    findings: list[Finding] = []
    for scanner in scanners:
        for finding in scanner.scan(root, files, text_cache):
            key = (finding.id, finding.location, finding.line, finding.evidence)
            if key in dedupe:
                continue
            dedupe.add(key)
            findings.append(finding)

    findings = filter_suppressed_findings(findings, scan_config.suppressions)
    findings = filter_baselined_findings(findings, load_baseline_fingerprints(baseline_path))
    findings.sort(key=lambda item: (item.location, item.line or 0, item.id))
    return ScanReport(root=root, findings=tuple(findings))
