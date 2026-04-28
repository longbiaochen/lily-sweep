# Roadmap

## Phase 0: Working Scanner Skeleton

- text + JSON output
- SARIF output and GitHub Actions example
- built-in rulepack
- harness guardrail heuristics
- repo-local config file
- config suppressions and generated baselines
- `init` command for config, workflow, and baseline scaffolding
- ROS control-plane heuristics
- scenario affordance heuristics
- sample unsafe fixture

## Phase 1: Embodied-System Depth

- ROS topic / service / action graph inspection
- clearer sim-vs-real interface tracing
- actuator capability inventory
- network-exposed robot control endpoint discovery
- SARIF output for CI

## Phase 2: Scene and Workflow Semantics

- structured scene manifest schema
- business-workflow risk scoring
- multi-agent escalation and conflict analysis
- prompt-injection-to-physical-action tracing

## Phase 3: Deployment Integration

- GitHub Action
- policy baselines per environment
- suppression file for accepted risks
- signed scan report for deployment gates
