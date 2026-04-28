from __future__ import annotations

from pathlib import Path

from lily_sweep.models import Finding


class Scanner:
    name = "base"

    def scan(self, root: Path, files: list[Path], text_cache: dict[Path, str]) -> list[Finding]:
        raise NotImplementedError
