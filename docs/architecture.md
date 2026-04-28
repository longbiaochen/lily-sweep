# Architecture

## Goal

LilySweep is a preflight auditor, not a runtime controller. Its job is to inspect a codebase and its adjacent deployment artifacts before an embodied agent is trusted with live execution.

## Scan Pipeline

1. File discovery
   - Walk the target path.
   - Skip bulky or generated directories such as `.git`, `node_modules`, `dist`, `build`, and virtual environments.
   - Skip LilySweep metadata files such as `lilysweep.json`, `lilysweep-baseline.json`, `lilysweep.yml`, and `lily-sweep.sarif`.
2. Text ingestion
   - Read likely text files with tolerant UTF-8 decoding.
   - Ignore obvious binary blobs.
   - Apply repo-level exclusions from `lilysweep.json` when present.
3. Scanner fan-out
   - Pattern scanner: regex signatures over files.
   - Harness scanner: repo-wide heuristics over agent control surfaces.
   - ROS control scanner: robot middleware surfaces such as topics, services, actions, and rosbridge exposure.
   - Scenario scanner: file-level scene affordance review.
4. Normalized findings
   - Each finding carries an ID, severity, category, location, evidence, and remediation.
   - A stable fingerprint is attached for baseline suppression.
5. Reporting
   - Text output for humans.
   - JSON output for CI or downstream tooling.
   - SARIF output for GitHub code scanning and other SARIF consumers.
   - Threshold-based exit codes via `--fail-on`.
6. Filtering
   - Repo config suppressions remove explicit accepted exceptions.
   - Baseline fingerprints remove existing accepted findings during CI adoption.

## Scanner Model

### Pattern Scanner

Purpose:

- catch concrete, high-signal hazards cheaply
- keep rules data-driven in `builtin_rules.json`

Good fits:

- `shell=True`
- `os.system(...)`
- hardcoded secrets
- wildcard tool allowlists
- destructive shell commands

### Harness Scanner

Purpose:

- reason about the agent control plane as a whole
- detect missing guardrails that cannot be expressed by one-line regex alone

Current heuristics:

- unguarded high-risk actuator routes
- wildcard or allow-all tool grants
- missing human approval gate
- missing dry-run capability
- missing action budget or rate limit
- missing rollback or emergency stop
- ambiguous simulation vs real-hardware boundary

### ROS Control Scanner

Purpose:

- detect high-risk ROS control surfaces before they are exposed to an agent
- catch middleware-layer mistakes that ordinary code scanning misses

Current heuristics:

- dangerous topics such as `/cmd_vel`, `/joint_trajectory`, `/gripper_command`
- dangerous services such as door or elevator actuation endpoints
- dangerous actions such as arm or pallet movement
- rosbridge on `0.0.0.0` with wildcard exposure
- mixed simulation and real-hardware indicators in one bringup surface

### Scenario Scanner

Purpose:

- find “ordinary-looking but toxic” operational affordances in deployment scenes

Current hazard families:

- crowd-dense human zones
- access-control surfaces such as doors, elevators, and turnstiles
- heavy machinery such as forklifts, vehicles, robot arms, and conveyors
- energy / toxic hazards such as batteries, chemicals, lasers, and high voltage

## Design Principles

- Static-first, scenario-aware, evidence-oriented.
- Default to explainable heuristics before ML scoring.
- Keep each finding actionable; the remediation should tell the operator what boundary or control is missing.
- Treat sim-to-real ambiguity as a first-class risk, not a mere config smell.
