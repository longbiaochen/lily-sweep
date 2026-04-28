from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from lily_sweep.baseline import build_baseline_payload
from lily_sweep.engine import scan_path


DEFAULT_CONFIG = {
    "exclude_paths": [
        "generated/**",
        "vendor/**",
        "third_party/**",
        "build/**",
        "dist/**",
    ],
    "ros": {
        "dangerous_topics": [
            "/cmd_vel",
            "/joint_trajectory",
            "/gripper_command",
        ],
        "dangerous_services": [
            "/door_unlock",
            "/elevator_control",
            "/release_brake",
        ],
        "dangerous_actions": [
            "/follow_joint_trajectory",
            "/navigate_to_pose",
        ],
    },
    "suppressions": [
        {
            "id": "example-finding-id",
            "location": "path/to/file.py",
            "evidence_contains": "example evidence",
            "reason": "replace this example with a real accepted-risk reason",
        }
    ],
}

WORKFLOW_TEMPLATE = """name: LilySweep

on:
  pull_request:
  push:
    branches:
      - main

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install LilySweep
        run: python -m pip install -e .

      - name: Generate SARIF
        run: python -m lily_sweep scan . --format sarif --output lily-sweep.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: lily-sweep.sarif

      - name: Gate high-severity findings
        run: |
          if [ -f lilysweep-baseline.json ]; then
            python -m lily_sweep scan . --baseline lilysweep-baseline.json --fail-on high
          else
            python -m lily_sweep scan . --fail-on high
          fi
"""


@dataclass(frozen=True)
class InitOptions:
    target: Path
    include_github: bool = True
    with_baseline: bool = False
    force: bool = False
    dry_run: bool = False


@dataclass(frozen=True)
class InitResult:
    planned: tuple[Path, ...]
    written: tuple[Path, ...]
    skipped: tuple[Path, ...]


def init_project(options: InitOptions) -> InitResult:
    target = options.target.expanduser().resolve()
    planned_writes: dict[Path, str] = {
        target / "lilysweep.json": json.dumps(DEFAULT_CONFIG, indent=2) + "\n",
    }
    if options.include_github:
        planned_writes[target / ".github" / "workflows" / "lilysweep.yml"] = WORKFLOW_TEMPLATE

    written: list[Path] = []
    skipped: list[Path] = []

    if not options.dry_run:
        target.mkdir(parents=True, exist_ok=True)

    for path, content in planned_writes.items():
        if path.exists() and not options.force:
            skipped.append(path)
            continue
        if options.dry_run:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        written.append(path)

    baseline_path = target / "lilysweep-baseline.json"
    if options.with_baseline:
        if baseline_path.exists() and not options.force:
            skipped.append(baseline_path)
        elif not options.dry_run:
            report = scan_path(target)
            payload = build_baseline_payload(report)
            baseline_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            written.append(baseline_path)

    planned = tuple(planned_writes)
    if options.with_baseline:
        planned = (*planned, baseline_path)
    return InitResult(planned=planned, written=tuple(written), skipped=tuple(skipped))
