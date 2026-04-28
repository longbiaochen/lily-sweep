from __future__ import annotations

import json
from pathlib import Path

from lily_sweep.models import ROSPolicy, ScanConfig, Suppression

DEFAULT_CONFIG_NAMES = ("lilysweep.json", ".lilysweep.json")


def _repo_root_for_config(target: Path) -> Path:
    return target if target.is_dir() else target.parent


def find_config_file(target: Path, explicit_path: str | None = None) -> Path | None:
    if explicit_path:
        return Path(explicit_path).expanduser().resolve()

    repo_root = _repo_root_for_config(target)
    for name in DEFAULT_CONFIG_NAMES:
        candidate = repo_root / name
        if candidate.is_file():
            return candidate
    return None


def load_scan_config(target: Path, explicit_path: str | None = None) -> ScanConfig:
    config_path = find_config_file(target, explicit_path=explicit_path)
    if not config_path:
        return ScanConfig()

    payload = json.loads(config_path.read_text(encoding="utf-8"))
    ros_block = payload.get("ros", {})
    suppression_blocks = payload.get("suppressions", [])
    return ScanConfig(
        exclude_paths=tuple(payload.get("exclude_paths", [])),
        ros=ROSPolicy(
            dangerous_topics=tuple(ros_block.get("dangerous_topics", [])),
            dangerous_services=tuple(ros_block.get("dangerous_services", [])),
            dangerous_actions=tuple(ros_block.get("dangerous_actions", [])),
        ),
        suppressions=tuple(
            Suppression(
                id=suppression.get("id"),
                location=suppression.get("location"),
                line=suppression.get("line"),
                evidence_contains=suppression.get("evidence_contains"),
                reason=suppression.get("reason", ""),
            )
            for suppression in suppression_blocks
        ),
    )
