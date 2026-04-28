# LilySweep

LilySweep is a pre-deployment hazard scanner for embodied AI systems. It treats a repository, harness, toolchain, and scenario bundle the same way a careful cat owner treats a new home before bringing a cat in: scan first, identify the toxic affordances, and remove or fence them off before execution starts.

## What it does

LilySweep v0 focuses on four practical preflight checks:

1. Code-pattern scanning for dangerous execution surfaces such as `shell=True`, wildcard tool grants, hardcoded keys, and destructive commands.
2. Harness linting for missing execution guardrails such as human approval, dry-run gates, action budgets, emergency stop, rollback, and sim/real separation.
3. ROS control-plane scanning for dangerous topics, services, actions, remote rosbridge exposure, and mixed sim/real bringup.
4. Scenario review for high-risk environmental affordances such as elevators, badge doors, forklifts, crowd-dense zones, batteries, and high-voltage spaces.
5. CI-friendly reporting with text or JSON output and a `--fail-on` severity threshold.

## Quick Start

```bash
cd /Users/longbiao/Projects/lily-sweep
PYTHONPATH=src python3 -m lily_sweep scan examples/unsafe_warehouse_agent
PYTHONPATH=src python3 -m lily_sweep scan examples/unsafe_warehouse_agent --config examples/unsafe_warehouse_agent/lilysweep.json
PYTHONPATH=src python3 -m lily_sweep scan examples/unsafe_warehouse_agent --format json --fail-on high
PYTHONPATH=src python3 -m lily_sweep scan examples/unsafe_warehouse_agent --format sarif --output lily-sweep.sarif
PYTHONPATH=src python3 -m lily_sweep baseline examples/unsafe_warehouse_agent --output lilysweep-baseline.json
PYTHONPATH=src python3 -m lily_sweep init /path/to/repo --with-baseline
PYTHONPATH=src python3 -m unittest discover -s tests -p "test_*.py"
```

If you want the `lily-sweep` command directly, install the package in editable mode first:

```bash
python3 -m pip install -e .
```

## Example

The bundled fixture `examples/unsafe_warehouse_agent` intentionally mixes:

- unguarded actuator routes
- shell execution from agent-controlled input
- wildcard tool access
- missing approval / dry-run / rollback controls
- ROS control surfaces with wildcard rosbridge exposure
- forklift + crowd + elevator affordances in the scenario model

Running LilySweep on that fixture should return multiple `high` and `critical` findings.

## Initial Architecture

- `src/lily_sweep/scanners/patterns.py`
  Regex-driven file scanning for high-signal code and config hazards.
- `src/lily_sweep/scanners/harness.py`
  Repo-wide harness heuristics for missing guardrails and unsafe actuator exposure.
- `src/lily_sweep/scanners/ros_control.py`
  ROS-aware inspection for dangerous topics/services/actions and remote control-plane exposure.
- `src/lily_sweep/scanners/scenario.py`
  Scene-aware scanning for risky operational affordances.
- `src/lily_sweep/config.py`
  Repo-local config loading from `lilysweep.json`.
- `src/lily_sweep/builtin_rules.json`
  Built-in rulepack for fast iteration.

More detail lives in [docs/architecture.md](docs/architecture.md), [docs/rulepack.md](docs/rulepack.md), and [docs/roadmap.md](docs/roadmap.md).
CI and SARIF usage lives in [docs/ci.md](docs/ci.md).

## Why the name

LilySweep comes from the “remove the lilies before bringing the cat home” safety metaphor. In embodied AI, the lilies are not flowers; they are toxic affordances: high-risk tools, actuator endpoints, over-broad permissions, ambiguous sim-to-real boundaries, and ordinary-looking scene elements that can turn into physical or business incidents when an agent misplans.

## License

MIT.

## Repo Config

If a target repo contains `lilysweep.json`, LilySweep auto-loads it. Current supported keys:

```json
{
  "exclude_paths": ["generated/**", "vendor/**"],
  "ros": {
    "dangerous_topics": ["/custom_actuator_topic"],
    "dangerous_services": ["/custom_actuator_service"],
    "dangerous_actions": ["/custom_actuator_action"]
  },
  "suppressions": [
    {
      "id": "direct-actuator-surface",
      "location": "ros/bringup.launch.py",
      "evidence_contains": "/cmd_vel",
      "reason": "covered by a stronger ROS-specific finding"
    }
  ]
}
```

For CI adoption on an existing repo, generate a baseline and scan against it:

```bash
PYTHONPATH=src python3 -m lily_sweep baseline /path/to/repo --output lilysweep-baseline.json
PYTHONPATH=src python3 -m lily_sweep scan /path/to/repo --baseline lilysweep-baseline.json --fail-on high
```

Or scaffold the repo files in one step:

```bash
PYTHONPATH=src python3 -m lily_sweep init /path/to/repo --with-baseline
```
