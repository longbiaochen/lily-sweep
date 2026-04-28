from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from lily_sweep.baseline import build_baseline_payload
from lily_sweep.engine import scan_path
from lily_sweep.formatters import findings_at_or_above, render_report
from lily_sweep.init_project import InitOptions, init_project


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lily-sweep",
        description="Preflight hazard scanning for embodied AI systems.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a repository or deployment bundle.")
    scan_parser.add_argument("path", help="Repository or bundle path to scan.")
    scan_parser.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="Output format.")
    scan_parser.add_argument("--output", default="-", help="Output path, or '-' to print to stdout.")
    scan_parser.add_argument("--rules", help="Extra JSON pattern rule file to append.")
    scan_parser.add_argument("--config", help="Repo policy file such as lilysweep.json.")
    scan_parser.add_argument("--baseline", help="Baseline JSON file whose accepted findings should be ignored.")
    scan_parser.add_argument(
        "--fail-on",
        choices=("info", "low", "medium", "high", "critical"),
        help="Exit with code 2 when findings meet or exceed this severity.",
    )
    scan_parser.set_defaults(func=run_scan)

    baseline_parser = subparsers.add_parser("baseline", help="Generate a baseline from the current scan results.")
    baseline_parser.add_argument("path", help="Repository or bundle path to scan.")
    baseline_parser.add_argument("--rules", help="Extra JSON pattern rule file to append.")
    baseline_parser.add_argument("--config", help="Repo policy file such as lilysweep.json.")
    baseline_parser.add_argument(
        "--output",
        default="lilysweep-baseline.json",
        help="Output path, or '-' to print JSON to stdout.",
    )
    baseline_parser.set_defaults(func=run_baseline)

    init_parser = subparsers.add_parser("init", help="Create LilySweep config and CI files in a repository.")
    init_parser.add_argument("path", nargs="?", default=".", help="Repository path to initialize.")
    init_parser.add_argument("--with-baseline", action="store_true", help="Generate lilysweep-baseline.json after init.")
    init_parser.add_argument("--no-github", action="store_true", help="Do not create .github/workflows/lilysweep.yml.")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing LilySweep files.")
    init_parser.add_argument("--dry-run", action="store_true", help="Print planned files without writing them.")
    init_parser.set_defaults(func=run_init)
    return parser


def run_scan(args: argparse.Namespace) -> int:
    report = scan_path(
        args.path,
        extra_rule_file=args.rules,
        config_path=args.config,
        baseline_path=args.baseline,
    )
    rendered = render_report(report, args.format)
    if args.output == "-":
        _emit_stdout(rendered)
    else:
        Path(args.output).expanduser().write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote {args.format} scan report with {len(report.findings)} findings to {args.output}")

    if args.fail_on and findings_at_or_above(report.findings, args.fail_on):
        return 2
    return 0


def run_baseline(args: argparse.Namespace) -> int:
    report = scan_path(args.path, extra_rule_file=args.rules, config_path=args.config)
    payload = build_baseline_payload(report)
    rendered = json.dumps(payload, indent=2)
    if args.output == "-":
        _emit_stdout(rendered)
    else:
        Path(args.output).expanduser().write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote baseline with {len(report.findings)} accepted findings to {args.output}")
    return 0


def run_init(args: argparse.Namespace) -> int:
    result = init_project(
        InitOptions(
            target=Path(args.path),
            include_github=not args.no_github,
            with_baseline=args.with_baseline,
            force=args.force,
            dry_run=args.dry_run,
        )
    )
    if args.dry_run:
        print("LilySweep init would create:")
        for path in result.planned:
            print(f"  {path}")
        return 0

    for path in result.written:
        print(f"Wrote {path}")
    for path in result.skipped:
        print(f"Skipped existing {path}")
    if not result.written and not result.skipped:
        print("No LilySweep files were requested.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


def _emit_stdout(payload: str) -> None:
    try:
        print(payload)
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except OSError:
            pass
