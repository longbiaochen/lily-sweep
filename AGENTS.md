# Lily-Sweep Runbook

## Repo Scope

- Owner/escalation: Longbiao for scanner behavior and public claims.
- This repo owns preflight hazard scanning, rule quality, fixtures, and evidence-backed findings for embodied AI systems.
- Do not drift into runtime policy-engine claims unless the implementation actually supports them.

## Canonical Commands

- Example scan:

```bash
PYTHONPATH=src python3 -m lily_sweep scan examples/unsafe_warehouse_agent
```

- JSON/high-failure scan:

```bash
PYTHONPATH=src python3 -m lily_sweep scan examples/unsafe_warehouse_agent --format json --fail-on high
```

- Tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p "test_*.py"
```

## Routine Operations

| Trigger | Command | Expected Result | Failure Recovery |
| --- | --- | --- | --- |
| Add a scanner or rule family | Add unsafe fixture, add firing test, then run unittest command | Rule fires on the intended unsafe case | Narrow the signature or keep it disabled until fixture coverage is high-signal |
| Change CLI output/user-facing rule names | Run scan in text and JSON modes | README/docs/CLI output agree on rule names and severity | Update docs and tests in the same patch |

## Troubleshooting

| Trigger | Command | Expected Result | Failure Recovery |
| --- | --- | --- | --- |
| Rule is noisy | Add a safe fixture/counterexample and run tests | False-positive risk is visible in test output | Reduce scope or leave rule disabled until evidence improves |
| Scanner misses a known unsafe pattern | Add a minimal unsafe fixture line | Test fails before implementation and passes after | Keep implementation stdlib-first unless a dependency materially improves rule quality |

## Verification

- Run the unittest command for code/rule changes.
- Run at least one example scan when CLI output or severity behavior changes.
- Report exact commands in fenced blocks.

## Release/Deploy

- Keep README, rule docs, and CLI output as one public surface.
- Update remediation notes in docs when a rule is user-facing.

## Guardrails

- Prefer stdlib-first implementation.
- Keep built-in rules high-signal.
- Do not claim runtime enforcement unless the repo actually implements it.

## Known State

- Source package lives under `src/lily_sweep`.
- Current examples focus on `examples/unsafe_warehouse_agent`.

## Browser Automation Constraint
- Follow the global `~/.codex/AGENTS.md` official browser/GUI policy: Browser plugin for unauthenticated local/public rendering, Chrome plugin for signed-in/default-profile browser state, and Computer Use only for native desktop boundaries.
- Keep only repo-specific verification surfaces here; do not copy the full global policy block into this runbook.

## Worktree Policy

- Follow the global `~/.codex/AGENTS.md` worktree-first rule for Codex development: new non-read-only coding or multi-file documentation tasks should start in a dedicated Codex-managed worktree.
- Use the Local checkout only for read-only investigation, final handoff/inspection, tasks that must reuse a single running app/server, or when the user explicitly asks to stay local.
- Branch names should use `codex/<repo>-<short-task>`; manual long-lived worktree directories should use `~/Projects/<repo>-<short-task>`.
- Initialize dependencies inside each worktree and keep ports, databases, device/simulator state, build outputs, and ignored local config isolated per checkout.
- Preserve existing dirty checkouts. Inspect `git status --short` before editing, and do not stash, commit, remove, or migrate user changes unless explicitly asked.
- After merge or abandonment, clean up with `git worktree remove <path>` and use `git worktree prune` only for stale metadata.
